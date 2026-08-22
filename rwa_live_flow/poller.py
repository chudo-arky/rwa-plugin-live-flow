"""Фоновый опрос панели Remnawave: скорость VPN-трафика и живой онлайн.

Зачем свой опрос, а не БД админки:

- **скорость VPN** — у панели нет realtime-эндпоинта (убран в 2.7), зато
  счётчики xray `trafficUsedBytes` ноды и `usedTrafficBytes` юзера растут
  с точностью до байта и обновляются каждые ~30 с / ~15 с. Скорость =
  дельта между двумя последними РАЗНЫМИ значениями / прошедшее время.
  Это именно трафик xray (пользовательский), а не сетевой карты хоста, как
  `net_*_bps` агента rw-admin (там и SSH, и мониторинг, и панель↔нода).
- **онлайн/активные** — админка синкает юзеров из панели раз в 5 минут, а
  из API панели `onlineAt`/`lastConnectedNodeUuid` приходят живыми.

Состояние в памяти процесса бэкенда; задача `panel-poll` (``ScheduledTask``)
дёргает ``tick()`` раз в ``INTERVAL_S``. Гарантии:

- два тика не идут одновременно (``_tick_lock``; наложение логируется);
- у тика общий таймаут ``TICK_TIMEOUT_S`` и таймаут на каждый запрос;
- после ошибки — экспоненциальный backoff (тики пропускаются);
- ошибки API и кривые ответы не роняют задачу: последний удачный срез остаётся,
  наружу уходит только код (``panel_unavailable`` / ``panel_timeout`` /
  ``panel_invalid_response``), детали — в лог;
- ``users`` больше ``MAX_USERS`` не читаем — срез помечается ``truncated``.

⚠️ Один процесс = один poller. При нескольких uvicorn-воркерах каждый опрашивает
панель сам (нагрузка ×N, данные у каждого свои, но корректные) — см. README.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

INTERVAL_S = 15                 # счётчики юзеров панель двигает ~раз в 15 с — чаще опрашивать незачем
TICK_TIMEOUT_S = 40.0           # весь цикл: не дольше этого (иначе следующий тик накладывался бы)
REQUEST_TIMEOUT_S = 20.0        # один запрос к панели
BACKOFF_BASE_S = 15.0           # после ошибки: 15, 30, 60, 120 … до BACKOFF_MAX_S
BACKOFF_MAX_S = 300.0
# Счётчик ноды панель двигает каждые ~30 с, юзера — чаще. Если значение не
# менялось дольше IDLE_S — считаем скорость нулевой, а не держим старую.
NODE_IDLE_S = 75.0
USER_IDLE_S = 60.0
# Окно «активен»: onlineAt не старше стольких секунд ОТ ТЕКУЩЕГО ВРЕМЕНИ.
ONLINE_WINDOW_S = 180.0
# Допуск на рассинхрон часов панели и бэкенда: onlineAt «из будущего» не
# дальше этого считаем нормальным.
CLOCK_SKEW_S = 30.0
USERS_PAGE = 500
MAX_USERS = 20000               # дальше не листаем; срез помечается truncated


def _safe_int(value: Any, default: int | None = 0) -> int | None:
    """int из чего угодно; не число — ``default``. Для счётчиков панели и id."""
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _parse_ts(value: Any) -> datetime | None:
    """ISO-8601 → aware timezone.utc datetime. Naive считаем timezone.utc, ``Z`` понимаем, мусор → None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class _Rate:
    """Скорость по монотонному счётчику: два последних РАЗНЫХ значения."""

    __slots__ = ("last_val", "last_ts", "prev_val", "prev_ts")

    def __init__(self) -> None:
        self.last_val: int | None = None
        self.last_ts: float = 0.0
        self.prev_val: int | None = None
        self.prev_ts: float = 0.0

    def push(self, val: int | None, now: float) -> None:
        if val is None:
            return
        if self.last_val is None:
            self.last_val, self.last_ts = val, now
            return
        if val != self.last_val:
            # Сброс счётчика (trafficResetDay / ручной reset) — начинаем заново,
            # отрицательной скорости не бывает.
            if val < self.last_val:
                self.prev_val, self.prev_ts = None, 0.0
            else:
                self.prev_val, self.prev_ts = self.last_val, self.last_ts
            self.last_val, self.last_ts = val, now

    def bps(self, now: float, idle_s: float) -> float:
        if self.last_val is None or self.prev_val is None:
            return 0.0
        if now - self.last_ts > idle_s:
            return 0.0
        dt = self.last_ts - self.prev_ts
        if dt <= 0:
            return 0.0
        return max(0.0, (self.last_val - self.prev_val) / dt)


class PanelResponseError(ValueError):
    """Ответ панели не той формы — это ошибка опроса, а не «пустой список»."""


def _response_list(payload: Any, key: str) -> tuple[list, int | None]:
    """``{"response": {key: [...], "total": N}}`` → (список, total). Иное — PanelResponseError."""
    if not isinstance(payload, dict):
        raise PanelResponseError("invalid panel response: not an object")
    response = payload.get("response")
    if not isinstance(response, dict):
        raise PanelResponseError("invalid panel response: no response object")
    value = response.get(key)
    if not isinstance(value, list):
        raise PanelResponseError(f"invalid panel response: {key} is not a list")
    return value, _safe_int(response.get("total"), None)


def _nodes_list(payload: Any) -> list:
    """``{"response": [...]}`` → список нод. Иное — PanelResponseError."""
    if not isinstance(payload, dict):
        raise PanelResponseError("invalid nodes response: not an object")
    value = payload.get("response")
    if not isinstance(value, list):
        raise PanelResponseError("invalid nodes response: response is not a list")
    return value


def _workers_hint() -> int | None:
    """Сколько воркеров у бэкенда, если это видно из окружения (иначе None)."""
    for key in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_WORKERS"):
        n = _safe_int(os.environ.get(key), None)
        if n:
            return n
    return None


class PanelPoller:
    def __init__(self) -> None:
        self._node_rates: dict[str, _Rate] = {}
        self._user_rates: dict[str, _Rate] = {}
        self.nodes: dict[str, dict] = {}     # uuid → {name, users_online, connected, disabled, traffic_total}
        self.users: dict[str, dict] = {}     # str(id панели) → {id, short_uuid, username, email, telegram_id, tag, online_at, node_uuid, traffic_total}
        self.as_of: float | None = None   # time.time() последнего удачного тика
        self.error: str | None = None     # код для API: panel_unavailable | panel_timeout | panel_invalid_response | None
        self.truncated = False               # юзеров больше MAX_USERS — срез неполный
        self.ticks_ok = 0
        self.failures = 0                    # подряд; задаёт backoff
        self._next_allowed = 0.0             # time.time(), раньше которого тик пропускаем (backoff)
        self._state_lock = asyncio.Lock()
        self._tick_lock = asyncio.Lock()
        self._warned_workers = False

    # ── опрос ────────────────────────────────────────────────────────
    async def tick(self, logger_: Any = None) -> None:
        """Один цикл опроса. Не накладывается сам на себя, уважает backoff."""
        log = logger_ or logger
        if self._tick_lock.locked():
            log.warning("live_flow: previous panel poll still running — tick skipped")
            return
        now = time.time()
        if now < self._next_allowed:
            return
        async with self._tick_lock:
            try:
                await asyncio.wait_for(self._tick_impl(log), timeout=TICK_TIMEOUT_S)
            except (TimeoutError, asyncio.TimeoutError):
                self._fail("panel_timeout", log, "live_flow: panel poll timed out after %.0fs", TICK_TIMEOUT_S)
            except asyncio.CancelledError:
                raise
            except PanelResponseError as exc:
                # Прошлый срез НЕ трогаем: кривая структура ≠ «никого нет».
                self._fail("panel_invalid_response", log, "live_flow: %s", str(exc))
            except Exception:  # noqa: BLE001 — срез остаётся прошлый, задача живёт
                self._fail("panel_unavailable", log, "live_flow: panel poll failed", exc_info=True)

    def _fail(self, code: str, log: Any, msg: str, *args: Any, exc_info: bool = False) -> None:
        self.failures += 1
        self.error = code
        delay = min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2 ** min(self.failures - 1, 6)))
        self._next_allowed = time.time() + delay
        log.warning(msg + " (failures=%d, next try in %.0fs)", *args, self.failures, delay, exc_info=exc_info)

    async def _fetch(self, coro):
        return await asyncio.wait_for(coro, timeout=REQUEST_TIMEOUT_S)

    async def _tick_impl(self, log: Any) -> None:
        from web.backend.core.plugin_api import panel_api

        api = panel_api()
        if not self._warned_workers:
            self._warned_workers = True
            w = _workers_hint()
            if w and w > 1:
                log.warning("live_flow: %d backend workers detected — each polls the panel separately (load x%d); see README", w, w)

        node_items = _nodes_list(await self._fetch(api.get_nodes(skip_cache=True)))
        users: list[dict] = []
        truncated = False
        start = 0
        total: int | None = None
        while True:
            chunk, total = _response_list(await self._fetch(api.get_users(start=start, size=USERS_PAGE, skip_cache=True)), "users")
            users.extend(u for u in chunk if isinstance(u, dict))
            if len(chunk) < USERS_PAGE:
                break
            start += USERS_PAGE
            if start >= MAX_USERS:
                # Ровно MAX_USERS — не усечение: сверяемся с total панели, если он есть.
                truncated = total is None or total > start
                if truncated:
                    log.warning("live_flow: users > %d — panel poll truncated", MAX_USERS)
                break

        now = time.time()
        async with self._state_lock:
            new_nodes: dict[str, dict] = {}
            for n in node_items:
                if not isinstance(n, dict):
                    continue
                uuid = str(n.get("uuid") or "")
                if not uuid:
                    continue
                total = _safe_int(n.get("trafficUsedBytes"), None)
                self._node_rates.setdefault(uuid, _Rate()).push(total, now)
                new_nodes[uuid] = {
                    "name": n.get("name"),
                    "users_online": _safe_int(n.get("usersOnline"), 0),
                    "connected": bool(n.get("isConnected")),
                    "disabled": bool(n.get("isDisabled")),
                    "traffic_total": total,
                }
            new_users: dict[str, dict] = {}
            for u in users:
                # ⚠️ В API панели 3.x у юзера НЕТ поля uuid (есть id, shortUuid,
                # vlessUuid); users.uuid админки — её собственный. Ключ здесь —
                # числовой id панели (он же users.id в БД админки).
                uid = _safe_int(u.get("id"), None)
                if uid is None:
                    continue
                key = str(uid)
                ut = u.get("userTraffic")
                if not isinstance(ut, dict):
                    ut = {}
                total = _safe_int(ut.get("usedTrafficBytes"), None)
                self._user_rates.setdefault(key, _Rate()).push(total, now)
                new_users[key] = {
                    "id": uid,
                    "short_uuid": u.get("shortUuid"),
                    "username": u.get("username"),
                    "email": u.get("email"),
                    "telegram_id": _safe_int(u.get("telegramId"), None),
                    "tag": u.get("tag"),
                    "online_at": _parse_ts(ut.get("onlineAt")),
                    "node_uuid": (str(ut.get("lastConnectedNodeUuid")) if ut.get("lastConnectedNodeUuid") else None),
                    "traffic_total": total,
                }
            self.nodes = new_nodes
            self.users = new_users
            # Забытые ноды/юзеры — выкинуть трекеры, чтобы память не росла.
            for k in list(self._node_rates):
                if k not in new_nodes:
                    del self._node_rates[k]
            for k in list(self._user_rates):
                if k not in new_users:
                    del self._user_rates[k]
            self.as_of = now
            self.error = None
            self.truncated = truncated
            self.failures = 0
            self._next_allowed = 0.0
            self.ticks_ok += 1
        if self.ticks_ok == 1:
            log.info("live_flow: panel poll ok — nodes=%d users=%d", len(new_nodes), len(new_users))

    # ── чтение ───────────────────────────────────────────────────────
    @property
    def fresh(self) -> bool:
        return self.as_of is not None and (time.time() - self.as_of) < 4 * INTERVAL_S

    def age_s(self) -> float | None:
        return None if self.as_of is None else time.time() - self.as_of

    def node_bps(self, uuid: str) -> float | None:
        r = self._node_rates.get(uuid)
        return None if r is None else r.bps(time.time(), NODE_IDLE_S)

    def user_bps(self, uid: str) -> float | None:
        r = self._user_rates.get(str(uid))
        return None if r is None else r.bps(time.time(), USER_IDLE_S)

    def active_users(self, now: datetime | None = None) -> list[tuple[str, dict]]:
        """(id, user) для юзеров с onlineAt не старше окна ОТ ТЕКУЩЕГО ВРЕМЕНИ.

        Если панель перестала обновлять onlineAt, активных становится 0, даже
        когда API отвечает — именно так и должно быть.
        """
        now = now or datetime.now(timezone.utc)
        out = []
        for uid, u in self.users.items():
            oa = u.get("online_at")
            if oa is None:
                continue
            age = (now - oa).total_seconds()
            if -CLOCK_SKEW_S <= age <= ONLINE_WINDOW_S:
                out.append((uid, u))
        return out

    def active_by_node(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _uid, u in self.active_users():
            nu = u.get("node_uuid")
            if nu:
                counts[nu] = counts.get(nu, 0) + 1
        return counts

    def online_ref(self) -> datetime | None:
        """Свежайший onlineAt среди юзеров — справочно («срез панели» в шапке)."""
        ts = [u["online_at"] for u in self.users.values() if u.get("online_at")]
        return max(ts) if ts else None

    def online_ref_iso(self) -> str | None:
        ref = self.online_ref()
        return ref.astimezone(timezone.utc).isoformat() if ref else None


POLLER = PanelPoller()
