"""Доли трафика по веткам выходов ноды: опрос ``GET /api/system/nodes/metrics``.

Зачем отдельный модуль, а не ещё один запрос в ``poller``: у общего тика один
``except`` на всё, и сбой этого источника пометил бы весь срез
``panel_unavailable`` и включил бы backoff — схема замерла бы целиком. Здесь
свой замок, свой backoff и свой код ошибки; когда метрик нет, схема выглядит
ровно как до этого модуля.

🔴 **Панель отдаёт не байты, а человекочитаемые строки** вида ``"12.34 GiB"``
(``prettyBytesUtil`` поверх xbytes, IEC; ровный ноль — просто ``"0"``). Шаг
строки — 0.01 её единицы: на GiB это 10.7 МБ, на TiB — 11 ГБ. Счётчик
кумулятивный с момента старта ``remnawave-scheduler`` и растёт, то есть
разрешение со временем ПАДАЕТ. Отсюда два решения:

- считаем **доли**, а не Мбит/с: ``share_i = Δ_i / Σ Δ`` по веткам ноды;
- дельту берём не между соседними тиками, а по окну ``WINDOW_S`` (скользящий
  буфер снимков), и отдаём хоть что-то, только когда суммарная дельта переросла
  шаг квантования — иначе схема тихо показывала бы неподвижные доли и врала.

На схеме доли не печатаются: по ним решается, к каким веткам тянуть линию
(за окно по ветке реально что-то прошло), а расклад в процентах — в подсказке
ноды.

Точного режима нет и не будет: сырые counters с ``:METRICS_PORT/metrics``
панели дали бы целые байты, но требуют своего URL и пароля из ``.env`` панели,
то есть настройки сверх установки плагина.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import deque
from typing import Any

logger = logging.getLogger(__name__)

INTERVAL_S = 30                 # чаще бессмысленно: панель двигает эти счётчики раз в 30 с
TICK_TIMEOUT_S = 40.0
REQUEST_TIMEOUT_S = 20.0
BACKOFF_BASE_S = 30.0
BACKOFF_MAX_S = 600.0
WINDOW_S = 600.0                # окно для дельт: чем длиннее, тем меньше мешает квантование
SNAPSHOTS = int(WINDOW_S // INTERVAL_S) + 1
MIN_WINDOW_S = 90.0             # пока окно короче — доли не показываем, они ещё шумные
STALE_S = 3 * INTERVAL_S        # последний снимок ноды старше — долей нет: опрос падает или нода пропала из ответа
QUANTUM_FACTOR = 2.0            # суммарная дельта должна перерасти столько шагов квантования

# Служебные теги xray самой панели — на схеме их нет и в долях быть не должно.
SERVICE_TAGS = frozenset({"REMNAWAVE_API", "REMNAWAVE_API_INBOUND", "RW_TB_OUTBOUND_BLOCK"})

_UNITS = {"B": 1}
for _i, _u in enumerate(("KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"), start=1):
    _UNITS[_u] = 1024 ** _i
_IEC_RE = re.compile(r"^(\d+(?:\.\d+)?) (" + "|".join(_UNITS) + r")$")


def parse_iec(s: Any) -> int | None:
    """``"12.34 GiB"`` → байты. Ровный ноль панель пишет как ``"0"`` без единицы.

    Не строка этой формы (None, мусор, отрицательное число) → ``None``, то есть
    «неизвестно», а не ноль: нулём такую ветку подписывать нельзя.
    """
    if isinstance(s, (int, float)) and not isinstance(s, bool):
        return int(s) if s >= 0 else None
    txt = str(s or "").strip()
    if txt == "0":
        return 0
    m = _IEC_RE.match(txt)
    if not m:
        return None
    return int(float(m.group(1)) * _UNITS[m.group(2)])


def quantum(s: Any) -> int:
    """Шаг строки — 0.01 её единицы: меньшую разницу панель показать не может.
    У ``"0"`` единица ещё не известна, берём 1 байт."""
    m = _IEC_RE.match(str(s or "").strip())
    return max(1, _UNITS[m.group(2)] // 100) if m else 1


def _nodes_of(payload: Any) -> list:
    """``{"response": {"nodes": [...]}}`` → список.

    Иное — пустой список, и это НЕ ошибка запроса: панель отдаёт ``{nodes: []}``
    в том числе при собственной ошибке чтения своего ``/metrics``, отличить
    одно от другого по ответу нельзя.
    """
    if not isinstance(payload, dict):
        return []
    r = payload.get("response")
    if not isinstance(r, dict):
        return []
    n = r.get("nodes")
    return n if isinstance(n, list) else []


class NodeMetricsPoller:
    """Скользящее окно снимков байт по тегам каждой ноды."""

    def __init__(self) -> None:
        # uuid → deque[(ts, {("in"|"out", тег): байты}, {("in"|"out", тег): шаг})]
        self._win: dict[str, deque] = {}
        self.as_of: float | None = None
        self.error: str | None = None   # metrics_unsupported | metrics_empty | metrics_timeout | metrics_unavailable
        self.failures = 0
        self._next_allowed = 0.0
        self._tick_lock = asyncio.Lock()

    # ── опрос ────────────────────────────────────────────────────────
    async def tick(self, logger_: Any = None) -> None:
        log = logger_ or logger
        if self._tick_lock.locked():
            log.warning("live_flow: previous metrics poll still running — tick skipped")
            return
        if time.time() < self._next_allowed:
            return
        async with self._tick_lock:
            try:
                await asyncio.wait_for(self._tick_impl(log), timeout=TICK_TIMEOUT_S)
            except (TimeoutError, asyncio.TimeoutError):
                self._fail("metrics_timeout", log, "live_flow: node metrics poll timed out")
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — окно остаётся прошлым, схема живёт
                self._fail("metrics_unavailable", log, "live_flow: node metrics poll failed", exc_info=True)

    def _fail(self, code: str, log: Any, msg: str, exc_info: bool = False) -> None:
        self.failures += 1
        self.error = code
        delay = min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2 ** min(self.failures - 1, 5)))
        self._next_allowed = time.time() + delay
        log.warning(msg + " (failures=%d, next try in %.0fs)", self.failures, delay, exc_info=exc_info)

    async def _tick_impl(self, log: Any) -> None:
        from web.backend.core.plugin_api import panel_api

        api = panel_api()
        if not hasattr(api, "get_nodes_metrics"):
            # Старая админка без метода — не сбой панели, просто источника нет.
            self.error = "metrics_unsupported"
            self._next_allowed = time.time() + BACKOFF_MAX_S
            return
        items = _nodes_of(await asyncio.wait_for(api.get_nodes_metrics(), timeout=REQUEST_TIMEOUT_S))
        now = time.time()
        if not items:
            self.error = "metrics_empty"
            self.failures = 0
            self.as_of = now
            return
        for n in items:
            if not isinstance(n, dict):
                continue
            uuid = str(n.get("nodeUuid") or n.get("uuid") or "")
            if not uuid:
                continue
            vals: dict[tuple[str, str], int] = {}
            steps: dict[tuple[str, str], int] = {}
            for kind, key in (("in", "inboundsStats"), ("out", "outboundsStats")):
                for st in n.get(key) or ():
                    if not isinstance(st, dict):
                        continue
                    tag = str(st.get("tag") or "")
                    if not tag or tag in SERVICE_TAGS:
                        continue
                    up, down = parse_iec(st.get("upload")), parse_iec(st.get("download"))
                    if up is None and down is None:
                        continue
                    vals[(kind, tag)] = (up or 0) + (down or 0)
                    steps[(kind, tag)] = max(quantum(st.get("upload")), quantum(st.get("download")))
            if vals:
                w = self._win.setdefault(uuid, deque(maxlen=SNAPSHOTS))
                # после перерыва в опросе в окне остались бы снимки старше WINDOW_S
                while w and now - w[0][0] > WINDOW_S:
                    w.popleft()
                w.append((now, vals, steps))
        # ноду убрали из панели — не держим её окно вечно
        self._win = {u: w for u, w in self._win.items() if now - w[-1][0] < WINDOW_S * 2}
        self.error = None
        self.failures = 0
        self.as_of = now

    # ── чтение ───────────────────────────────────────────────────────
    def age_s(self) -> float | None:
        return None if self.as_of is None else time.time() - self.as_of

    def shares(self, node_uuid: str, kind: str = "out") -> dict | None:
        """``{"shares": {тег: доля 0..1}, "window_s": …, "bytes": Σ Δ}`` или None.

        None — когда мерить ещё нечем: одного снимка мало, окно короткое,
        последний снимок старше ``STALE_S``, или суммарная дельта не переросла
        шаг квантования. Последнее на TiB-масштабе штатно, и «нет измерений»
        там честнее застывших долей.
        """
        win = self._win.get(node_uuid)
        if not win or len(win) < 2:
            return None
        # Окно чистится только удачным тиком. Когда опрос падает или панель
        # отдаёт пустой список, прошлые доли рисовали бы линии, которых уже
        # никто не мерил.
        if time.time() - win[-1][0] > STALE_S:
            return None
        (t0, v0, _), (t1, v1, s1) = win[0], win[-1]
        dt = t1 - t0
        if dt < MIN_WINDOW_S:
            return None
        deltas: dict[str, int] = {}
        step = 1
        for (k, tag), new in v1.items():
            if k != kind:
                continue
            old = v0.get((k, tag))
            # Тега не было в старом снимке или счётчик уехал вниз (рестарт
            # scheduler) — по этой ветке за это окно измерения нет.
            if old is None or new < old:
                continue
            if new == old:
                # По ветке за окно не прошло ничего. Это не «доля 0 %»: потока нет,
                # значит нет и линии на схеме — иначе к BLOCK тянется линия от
                # каждой ноды, а к пустым каскадам по одной на каждый тег.
                continue
            deltas[tag] = new - old
            step = max(step, s1.get((k, tag), 1))
        total = sum(deltas.values())
        if not deltas or total < step * QUANTUM_FACTOR:
            return None
        return {"shares": {t: d / total for t, d in deltas.items()}, "window_s": round(dt, 1), "bytes": total}


POLLER = NodeMetricsPoller()
