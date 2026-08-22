"""Unit-тесты poller: парсинг дат, окно «активен», скорость, блокировка тиков, пагинация."""
from __future__ import annotations

import asyncio
import sys
import types
from datetime import datetime, timedelta, timezone

import pytest

from rwa_live_flow import poller as P


# ── _parse_ts ──────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2026-08-22T12:00:00Z", datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)),
        ("2026-08-22T12:00:00+03:00", datetime(2026, 8, 22, 9, 0, tzinfo=timezone.utc)),
        ("2026-08-22T12:00:00", datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)),
        ("2026-08-22T12:00:00.123Z", datetime(2026, 8, 22, 12, 0, 0, 123000, tzinfo=timezone.utc)),
        ("", None),
        (None, None),
        ("garbage", None),
        (12345, None),
    ],
)
def test_parse_ts_normalizes_to_utc(raw, expected):
    got = P._parse_ts(raw)
    assert got == expected
    if got is not None:
        assert got.tzinfo is not None and got.utcoffset() == timedelta(0)


def test_parse_ts_mixed_aware_naive_comparable():
    a = P._parse_ts("2026-08-22T12:00:00Z")
    b = P._parse_ts("2026-08-22T12:00:30")
    assert (b - a).total_seconds() == 30


# ── _safe_int ──────────────────────────────────────────────────────
@pytest.mark.parametrize("v, d, exp", [("12", 0, 12), (3.9, 0, 3), (None, 0, 0), ("x", 7, 7), (True, 0, 0), (10**30, 0, 10**30)])
def test_safe_int(v, d, exp):
    assert P._safe_int(v, d) == exp


# ── active_users ───────────────────────────────────────────────────
def _poller_with(users):
    pl = P.PanelPoller()
    pl.users = users
    return pl


def test_active_users_uses_current_time_not_max_online_at():
    now = datetime(2026, 8, 22, 12, 10, tzinfo=timezone.utc)
    pl = _poller_with({
        "1": {"online_at": now - timedelta(seconds=60), "node_uuid": "n1"},
        "2": {"online_at": now - timedelta(seconds=P.ONLINE_WINDOW_S + 1), "node_uuid": "n1"},
        "3": {"online_at": None, "node_uuid": "n1"},
        "4": {"online_at": now + timedelta(seconds=10), "node_uuid": "n2"},          # лёгкий рассинхрон часов — ок
        "5": {"online_at": now + timedelta(seconds=P.CLOCK_SKEW_S + 5), "node_uuid": "n2"},  # слишком из будущего
    })
    ids = sorted(uid for uid, _ in pl.active_users(now=now))
    assert ids == ["1", "4"]


def test_all_stale_online_at_means_zero_active():
    now = datetime(2026, 8, 22, 12, 10, tzinfo=timezone.utc)
    pl = _poller_with({str(i): {"online_at": now - timedelta(minutes=20), "node_uuid": "n"} for i in range(5)})
    assert pl.active_users(now=now) == []
    assert pl.active_by_node() == {}


# ── _Rate ──────────────────────────────────────────────────────────
def test_rate_basic_and_idle_and_reset():
    r = P._Rate()
    r.push(1000, 0)
    assert r.bps(5, 75) == 0                       # одно значение — скорости нет
    r.push(1000, 10)
    r.push(4000, 30)
    assert abs(r.bps(35, 75) - 100) < 1e-9         # 3000 байт за 30 с
    r.push(4000, 40)
    r.push(4000, 60)
    assert r.bps(110, 75) == 0                     # без изменений дольше idle → 0
    r.push(100, 70)                                # сброс счётчика
    assert r.bps(75, 75) == 0                      # не отрицательная
    r.push(700, 100)
    assert abs(r.bps(105, 75) - 20) < 1e-9


# ── tick: блокировка наложений и пагинация ─────────────────────────
class _FakeApi:
    def __init__(self, users_total=3, delay=0.0, fail=False):
        self.users_total = users_total
        self.delay = delay
        self.fail = fail
        self.calls = 0

    async def get_nodes(self, skip_cache=True):
        self.calls += 1
        if self.fail:
            raise RuntimeError("boom http://panel.internal secret")
        await asyncio.sleep(self.delay)
        return {"response": [{"uuid": "n1", "name": "N1", "usersOnline": "5", "isConnected": True, "trafficUsedBytes": "100"},
                             "garbage", {"uuid": None}]}

    async def get_users(self, start=0, size=500, skip_cache=True):
        self.calls += 1
        await asyncio.sleep(self.delay)
        end = min(self.users_total, start + size)
        users = [{"id": i, "username": f"u{i}", "userTraffic": {"usedTrafficBytes": 10 * i, "onlineAt": "2026-08-22T12:00:00Z",
                                                                "lastConnectedNodeUuid": "n1"}} for i in range(start, end)]
        users.append("not-a-dict")
        users.append({"id": "abc"})  # id не число — пропускается
        return {"response": {"total": self.users_total, "users": users if start < self.users_total else []}}


@pytest.fixture
def fake_panel(monkeypatch):
    """Подменяем web.backend.core.plugin_api.panel_api на фейк."""
    holder = {}
    mod_web = types.ModuleType("web")
    mod_backend = types.ModuleType("web.backend")
    mod_core = types.ModuleType("web.backend.core")
    mod_api = types.ModuleType("web.backend.core.plugin_api")
    mod_api.panel_api = lambda: holder["api"]
    monkeypatch.setitem(sys.modules, "web", mod_web)
    monkeypatch.setitem(sys.modules, "web.backend", mod_backend)
    monkeypatch.setitem(sys.modules, "web.backend.core", mod_core)
    monkeypatch.setitem(sys.modules, "web.backend.core.plugin_api", mod_api)
    return holder


async def test_tick_parses_and_counts(fake_panel):
    fake_panel["api"] = _FakeApi(users_total=3)
    pl = P.PanelPoller()
    await pl.tick()
    assert pl.ticks_ok == 1 and pl.error is None
    assert set(pl.users) == {"0", "1", "2"}
    assert pl.nodes["n1"]["users_online"] == 5
    assert pl.truncated is False


async def test_concurrent_ticks_do_not_overlap(fake_panel):
    api = _FakeApi(users_total=3, delay=0.2)
    fake_panel["api"] = api
    pl = P.PanelPoller()
    await asyncio.gather(pl.tick(), pl.tick(), pl.tick())
    # один полный цикл = get_nodes + 1 страница users = 2 вызова; наложений нет
    assert api.calls == 2
    assert pl.ticks_ok == 1


async def test_pagination_limit_marks_truncated(fake_panel, monkeypatch):
    monkeypatch.setattr(P, "USERS_PAGE", 2)
    monkeypatch.setattr(P, "MAX_USERS", 4)
    fake_panel["api"] = _FakeApi(users_total=100)
    pl = P.PanelPoller()
    await pl.tick()
    assert pl.truncated is True
    assert len(pl.users) == 4


async def test_failure_sets_code_not_details_and_backoff(fake_panel):
    fake_panel["api"] = _FakeApi(fail=True)
    pl = P.PanelPoller()
    await pl.tick()
    assert pl.error == "panel_unavailable"
    assert "secret" not in (pl.error or "")
    assert pl.failures == 1 and pl._next_allowed > 0
    # следующий тик в окне backoff пропускается без обращения к API
    calls = fake_panel["api"].calls
    await pl.tick()
    assert fake_panel["api"].calls == calls


async def test_tick_timeout_sets_code(fake_panel, monkeypatch):
    monkeypatch.setattr(P, "TICK_TIMEOUT_S", 0.05)
    fake_panel["api"] = _FakeApi(delay=0.5)
    pl = P.PanelPoller()
    await pl.tick()
    assert pl.error == "panel_timeout"


async def test_invalid_panel_response_keeps_snapshot_and_sets_code(fake_panel):
    api = _FakeApi(users_total=3)
    fake_panel["api"] = api
    pl = P.PanelPoller()
    await pl.tick()
    assert pl.ticks_ok == 1 and len(pl.users) == 3

    class Broken:
        async def get_nodes(self, skip_cache=True):
            return {"response": [{"uuid": "n1", "name": "N1"}]}

        async def get_users(self, start=0, size=500, skip_cache=True):
            return {"response": {"unexpected": 1}}
    fake_panel["api"] = Broken()
    pl._next_allowed = 0.0
    await pl.tick()
    assert pl.error == "panel_invalid_response"
    assert pl.ticks_ok == 1 and len(pl.users) == 3       # прошлый срез цел
    assert pl.failures == 1 and pl._next_allowed > 0      # backoff включился


@pytest.mark.parametrize("total, expect_trunc", [(4, False), (5, True), (None, True)])
async def test_exact_limit_is_not_truncated(fake_panel, monkeypatch, total, expect_trunc):
    monkeypatch.setattr(P, "USERS_PAGE", 2)
    monkeypatch.setattr(P, "MAX_USERS", 4)

    class Api(_FakeApi):
        async def get_users(self, start=0, size=500, skip_cache=True):
            r = await super().get_users(start, size, skip_cache)
            r["response"]["total"] = total
            return r
    fake_panel["api"] = Api(users_total=max(total or 4, 4))
    pl = P.PanelPoller()
    await pl.tick()
    assert len(pl.users) == 4
    assert pl.truncated is expect_trunc


def test_response_list_helpers():
    with pytest.raises(P.PanelResponseError):
        P._response_list("x", "users")
    with pytest.raises(P.PanelResponseError):
        P._response_list({"response": {"users": "no"}}, "users")
    assert P._response_list({"response": {"users": [], "total": 0}}, "users") == ([], 0)
    with pytest.raises(P.PanelResponseError):
        P._nodes_list({"response": {"a": 1}})
    assert P._nodes_list({"response": []}) == []
