"""IP пользователей с ноды, когда access.log не читается: Connections API панели.

Штатный источник IP — ``user_connections``, куда пишет агент админки, разобрав
access.log. Там, где агента нет или он лога не видит, IP не появляются вовсе, и
списки «кто на ноде» остаются без адресов. Панель при этом знает их сама:
xray держит карту онлайн-IP, и панель отдаёт её по запросу.

Источник дополняющий, не замещающий: где строка ``user_connections`` есть, берётся
она — там IP пришёл вместе с тегом инбаунда и аутбаундов, чего этот путь не даёт.

🔴 **Только ``by-node``.** У ``by-user`` нода читает карту с ``reset: true`` и
очищает её в xray, ломая данные другим потребителям. ``by-node`` читает с
``reset=false`` и безопасен.

Механика панели (проверено на боевой 12.09.2026: job отрабатывает за ~1 с):

    POST /api/connections/by-node/{nodeUuid}  → {"response": {"jobId": "…"}}
    GET  /api/connections/by-node/{jobId}     → {"response": {isCompleted, isFailed,
                                                  result: {success, users:[{userId, ips:[…]}]}}}

Задача ``ScheduledTask`` — это ``while True: coro(); sleep(interval)``, поэтому
ждать job внутри тика нельзя: ``sleep`` заморозил бы всю задачу. Отсюда машина
состояний между тиками и обход нод по кругу.
"""
from __future__ import annotations

import asyncio
import logging
import math
import time
from typing import Any

logger = logging.getLogger(__name__)

INTERVAL_S = 15
SNAPSHOT_TTL_S = 90.0        # снимок свежее — не перезапрашиваем
SNAPSHOT_MAX_AGE_S = 300.0   # снимок старше (и старше двух кругов обхода) — не показываем вовсе
NODES_PER_TICK = 3           # на парке в 100 нод полный круг за ~8 мин: схема и так живёт на панельном онлайне
MAX_INFLIGHT = 10            # совпадает с concurrency очереди queryNodes у панели
JOB_TTL_S = 120.0            # job не ответил за это время — начинаем заново
REQUEST_TIMEOUT_S = 15.0
TICK_TIMEOUT_S = 30.0
BACKOFF_BASE_S = 30.0
BACKOFF_MAX_S = 600.0


def _job_id(payload: Any) -> str | None:
    r = (payload or {}).get("response") if isinstance(payload, dict) else None
    jid = r.get("jobId") if isinstance(r, dict) else None
    return str(jid) if jid else None


def _job_result(payload: Any) -> dict | None:
    """``{user_id: [ip, …]}`` — готовый результат, или None, если job ещё не готов.

    Нода не найдена или не на связи → job штатно завершается с
    ``success: false``: это не ошибка, а пустой снимок.
    """
    r = (payload or {}).get("response") if isinstance(payload, dict) else None
    if not isinstance(r, dict) or not r.get("isCompleted"):
        return None
    res = r.get("result")
    if not isinstance(res, dict) or not res.get("success"):
        return {}
    out: dict[str, list[str]] = {}
    for u in res.get("users") or ():
        if not isinstance(u, dict) or u.get("userId") is None:
            continue
        ips = [str(i.get("ip")) for i in (u.get("ips") or ()) if isinstance(i, dict) and i.get("ip")]
        out[str(u["userId"])] = ips
    return out


class ConnectionsPoller:
    """Снимки «кто на ноде и с каких IP», по одному на ноду, обновляются по кругу."""

    def __init__(self) -> None:
        # uuid → {phase: idle|posted, job, posted_at, ips, as_of, fails, retry_at}
        self._st: dict[str, dict] = {}
        self._cursor = 0
        self._round_s = 0.0             # сколько идёт полный круг обхода при текущем числе нод
        self.error: str | None = None   # connections_unsupported | connections_unavailable
        self.failures = 0
        self._next_allowed = 0.0
        self._tick_lock = asyncio.Lock()

    # ── чтение ───────────────────────────────────────────────────────
    def max_age_s(self) -> float:
        """Старше этого снимок не отдаётся.

        Порог плавает с размером парка: на 100 нодах штатный круг обхода ~8 мин,
        и снимок такого возраста — норма, а не сбой. Два круга без обновления —
        значит, обновить не получается, и прошлый адрес выдавать за текущий нельзя.
        """
        return max(SNAPSHOT_MAX_AGE_S, 2 * self._round_s)

    def ips(self, node_uuid: str) -> dict[str, list[str]] | None:
        """``{id пользователя: [IP, …]}`` или None, если снимка нет или он протух.

        Пустой список у пользователя — не ошибка: xray не кладёт в карту
        ``127.0.0.1`` и ``[::1]``, поэтому клиент за локальным прокси в ней
        просто отсутствует.
        """
        age = self.age_s(node_uuid)
        if age is None:
            return None
        return (self._st.get(node_uuid) or {}).get("ips")

    def age_s(self, node_uuid: str) -> float | None:
        """Возраст снимка ноды; None — снимка нет или он старше ``max_age_s``."""
        st = self._st.get(node_uuid) or {}
        if st.get("as_of") is None:
            return None
        age = time.time() - st["as_of"]
        return None if age > self.max_age_s() else age

    def user_ip(self, node_uuid: str, user_id) -> str | None:
        """Первый известный IP пользователя на этой ноде."""
        got = (self.ips(node_uuid) or {}).get(str(user_id)) or []
        return got[0] if got else None

    # ── опрос ────────────────────────────────────────────────────────
    async def tick(self, nodes: dict[str, dict], logger_: Any = None) -> None:
        """``nodes`` — срез панели из poller: uuid → {connected, disabled}."""
        log = logger_ or logger
        if self._tick_lock.locked():
            log.warning("live_flow: previous connections sweep still running — tick skipped")
            return
        if time.time() < self._next_allowed:
            return
        async with self._tick_lock:
            try:
                await asyncio.wait_for(self._tick_impl(nodes, log), timeout=TICK_TIMEOUT_S)
            except (TimeoutError, asyncio.TimeoutError):
                self._fail("connections_unavailable", log, "live_flow: connections sweep timed out")
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — снимки остаются прошлыми, схема живёт
                self._fail("connections_unavailable", log, "live_flow: connections sweep failed", exc_info=True)

    def _fail(self, code: str, log: Any, msg: str, exc_info: bool = False) -> None:
        self.failures += 1
        self.error = code
        delay = min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2 ** min(self.failures - 1, 5)))
        self._next_allowed = time.time() + delay
        log.warning(msg + " (failures=%d, next try in %.0fs)", self.failures, delay, exc_info=exc_info)

    async def _tick_impl(self, nodes: dict[str, dict], log: Any) -> None:
        from web.backend.core.plugin_api import panel_api

        api = panel_api()
        if not (hasattr(api, "fetch_users_ips_by_node") and hasattr(api, "get_fetch_users_ips_result")):
            self.error = "connections_unsupported"
            self._next_allowed = time.time() + BACKOFF_MAX_S
            return

        live = [u for u, n in (nodes or {}).items() if n.get("connected") and not n.get("disabled")]
        for gone in set(self._st) - set(live):
            self._st.pop(gone, None)
        if not live:
            return
        now = time.time()
        self._round_s = math.ceil(len(live) / NODES_PER_TICK) * INTERVAL_S
        ok = failed = 0

        # 1. Забрать готовые ответы: они дешёвые и освобождают место под новые job.
        for uuid in [u for u in live if (self._st.get(u) or {}).get("phase") == "posted"]:
            st = self._st[uuid]
            try:
                got = _job_result(await asyncio.wait_for(api.get_fetch_users_ips_result(st["job"]), timeout=REQUEST_TIMEOUT_S))
            except Exception:  # noqa: BLE001 — чаще всего 404: job протух, начнём заново
                st.update(phase="idle", job=None)
                self._node_failed(st, now)
                failed += 1
                continue
            ok += 1
            if got is None:
                # ещё считается; протухший job не держим вечно
                if now - st.get("posted_at", now) > JOB_TTL_S:
                    st.update(phase="idle", job=None)
                    self._node_failed(st, now)
                continue
            st.update(phase="idle", job=None, ips=got, as_of=now, fails=0, retry_at=0.0)

        # 2. Поставить новые job тем, у кого снимок устарел — по кругу, не больше K за тик.
        # Неудачная попытка тоже тратит место в тике: иначе при сплошных 403
        # (токену не выдали права на connections) тик обходил бы весь парк.
        inflight = sum(1 for u in live if (self._st.get(u) or {}).get("phase") == "posted")
        tried = 0
        order = live[self._cursor % len(live):] + live[: self._cursor % len(live)]
        for uuid in order:
            if tried >= NODES_PER_TICK or inflight >= MAX_INFLIGHT:
                break
            st = self._st.setdefault(uuid, {"phase": "idle", "job": None, "ips": None, "as_of": None, "fails": 0})
            if st["phase"] != "idle":
                continue
            if st["as_of"] is not None and now - st["as_of"] < SNAPSHOT_TTL_S:
                continue
            if now < st.get("retry_at", 0.0):
                continue
            tried += 1
            try:
                jid = _job_id(await asyncio.wait_for(api.fetch_users_ips_by_node(uuid), timeout=REQUEST_TIMEOUT_S))
            except Exception:  # noqa: BLE001 — нода могла отвалиться между срезами
                jid = None
            if not jid:
                self._node_failed(st, now)
                failed += 1
                continue
            st.update(phase="posted", job=jid, posted_at=now)
            inflight += 1
            ok += 1
        self._cursor = (self._cursor + tried) % max(1, len(live))
        if failed and not ok:
            # Ни один запрос не прошёл: это не «нода отвалилась», а панель или
            # права токена. Общий backoff и ошибка в легенде, а не тихий цикл.
            self._fail("connections_unavailable", log, "live_flow: every connections request failed")
            return
        self.error = None
        self.failures = 0

    @staticmethod
    def _node_failed(st: dict, now: float) -> None:
        """Своя пауза у ноды, которая не отвечает: остальные опрашиваются как обычно."""
        st["fails"] = st.get("fails", 0) + 1
        st["retry_at"] = now + min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2 ** min(st["fails"] - 1, 5)))


POLLER = ConnectionsPoller()
