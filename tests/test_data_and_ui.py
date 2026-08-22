"""Тесты разбора профилей, классификации сети и экранирования в UI-модуле."""
from __future__ import annotations

import re

import pytest

from rwa_live_flow import data as D
from rwa_live_flow.module import MODULE_JS


# ── профили: кривой JSON не роняет ─────────────────────────────────
class _Logger:
    def exception(self, *a, **k):
        pass

    def warning(self, *a, **k):
        pass


class _FakePanel:
    def __init__(self, payload):
        self.payload = payload

    async def get_config_profiles(self):
        return self.payload


@pytest.fixture
def fake_panel(monkeypatch):
    import sys
    import types

    holder = {}
    for name in ("web", "web.backend", "web.backend.core"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    api = types.ModuleType("web.backend.core.plugin_api")
    api.panel_api = lambda: holder["api"]
    monkeypatch.setitem(sys.modules, "web.backend.core.plugin_api", api)
    return holder


async def test_profiles_bad_shapes_do_not_raise(fake_panel):
    fake_panel["api"] = _FakePanel({"response": {"configProfiles": [
        "garbage",
        {"uuid": "p1", "name": "ok", "config": {"outbounds": [{"tag": "DIRECT", "protocol": "freedom", "settings": "x"}, "junk", {"protocol": "freedom"}],
                                                  "inbounds": [{"tag": "in1"}, 5]}},
        {"uuid": "p2", "name": "string-config", "config": '{"outbounds": [{"tag": "BLOCK", "protocol": "blackhole"}]}'},
        {"uuid": "p3", "name": "broken-json", "config": "{not json"},
        {"uuid": "p4", "name": "null-config", "config": None},
        {"name": "no-uuid"},
    ]}})
    out = await D._profiles_by_uuid(_Logger())
    assert set(out) == {"p1", "p2", "p3", "p4"}
    assert [o["tag"] for o in out["p1"]["outbounds"]] == ["DIRECT"]
    assert out["p1"]["inbounds"] == ["in1"]
    assert [o["tag"] for o in out["p2"]["outbounds"]] == ["BLOCK"]
    assert out["p3"]["outbounds"] == [] and out["p4"]["outbounds"] == []


async def test_profiles_request_failure_returns_none(fake_panel):
    class Boom:
        async def get_config_profiles(self):
            raise RuntimeError("x")
    fake_panel["api"] = Boom()
    assert await D._profiles_by_uuid(_Logger()) is None


def test_outbound_addr_shapes():
    assert D._outbound_addr({"settings": {"vnext": [{"address": "1.2.3.4"}]}}) == "1.2.3.4"
    assert D._outbound_addr({"settings": {"peers": [{"endpoint": "h.example:51820"}]}}) == "h.example"
    assert D._outbound_addr({"settings": "str"}) is None
    assert D._outbound_addr({}) is None


# ── классификация сети ─────────────────────────────────────────────
@pytest.mark.parametrize("is_mobile, ct, exp", [
    (True, None, "mobile"), (None, "mobile", "mobile"), (True, "mobile_isp", "mobile"),
    (False, "fixed", "fixed"), (False, None, "fixed"), (None, "residential", "fixed"),
    (None, None, "unknown"),
])
def test_net_class(is_mobile, ct, exp):
    assert D._net_class(is_mobile, ct) == exp


# ── SQL не кастует мусор напрямую ──────────────────────────────────
def test_sql_guards_against_garbage_casts():
    import inspect

    assert "~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}" in D._ONLINE_AT_SQL
    src = inspect.getsource(D.collect)
    assert "~ '^-?[0-9]+$'" in src and "viewPosition" in src
    # нигде не осталось прямого каста onlineAt/viewPosition без проверки формы
    assert "->>'viewPosition', '')::int" not in inspect.getsource(D)


# ── UI: всё из данных идёт через esc(), XSS-строки не попадают в разметку сырыми ──
XSS = ['"><script>alert(1)</script>', '"><img src=x onerror=alert(1)>', '& < > "']


def test_module_escapes_user_controlled_fields():
    js = MODULE_JS
    # имена нод, теги выходов, имена профилей/инбаундов, юзеры/IP/AS/гео/нода — только через esc(...)
    for field in ("n.name", "sk.tag", "n.profile", "r.ip", "r.as_name", "r.node", "u.user", "r.country", "r.city", "r.inbound", "u.tag", "c.title"):
        # допускаем использование в вычислениях (длина/сравнения), но не в конкатенации разметки без esc
        for m in re.finditer(r"['\"][^'\"]*<[^'\"]*['\"]\s*\+\s*" + re.escape(field) + r"\b", js):
            pytest.fail(f"{field} попадает в разметку без esc(): {m.group(0)[:60]}")
    assert "function esc(s)" in js and "replace(/[&<>\"]/g" in js
    # та же таблица замен, что в esc(): после неё в строке не остаётся сырых <, >, " и &
    table = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}
    for payload in XSS:
        out = re.sub(r'[&<>"]', lambda m: table[m.group(0)], payload)
        assert not re.search(r'[<>"]', out) and "&" not in out.replace("&amp;", "").replace("&lt;", "").replace("&gt;", "").replace("&quot;", "")


def test_module_fetches_with_no_store():
    assert MODULE_JS.count("cache: 'no-store'") >= 2


def test_profile_uuid_shapes():
    assert D._profile_uuid({"configProfile": {"activeConfigProfileUuid": "abc"}}) == "abc"
    assert D._profile_uuid({"configProfile": "invalid"}) is None
    assert D._profile_uuid('{"configProfile": {"activeConfigProfileUuid": "x"}}') == "x"
    assert D._profile_uuid("{bad") is None
    assert D._profile_uuid(None) is None


async def test_profiles_cache_serves_stale_on_failure(fake_panel, monkeypatch):
    monkeypatch.setattr(D, "PROFILES_TTL_S", 0.0)
    D._profiles_cache.update(ts=0.0, data=None, stale=False, last_log=0.0)
    fake_panel["api"] = _FakePanel({"response": {"configProfiles": [{"uuid": "p1", "name": "ok", "config": {}}]}})
    data, stale = await D._profiles_cached(_Logger())
    assert set(data) == {"p1"} and stale is False

    class Boom:
        async def get_config_profiles(self):
            raise RuntimeError("panel down")
    fake_panel["api"] = Boom()
    data2, stale2 = await D._profiles_cached(_Logger())
    assert data2 is not None and set(data2) == {"p1"} and stale2 is True   # последний удачный, помечен stale


def test_json_response_encodes_ip_and_datetime():
    import ipaddress
    import json
    from datetime import datetime, timezone

    from rwa_live_flow.routes import _json

    resp = _json({"ip": ipaddress.ip_address("203.0.113.7"), "ip6": ipaddress.ip_address("2001:db8::1"),
                  "ts": datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)})
    assert resp.status_code == 200
    body = json.loads(resp.body)
    assert body["ip"] == "203.0.113.7" and body["ip6"] == "2001:db8::1" and body["ts"].startswith("2026-08-22T12:00:00")
    assert resp.headers["cache-control"] == "private, no-store" and resp.headers["pragma"] == "no-cache"


def test_online_at_regex_rejects_garbage():
    rx = re.search(r"~ '([^']+)'", D._ONLINE_AT_SQL).group(1)
    pat = re.compile(rx.replace("\\\\", "\\"))
    assert pat.match("2026-08-22T12:00:00.180Z")
    assert pat.match("2026-08-22T12:00:00+03:00")
    assert not pat.match("2026-08-22Tgarbage")
    assert not pat.match("garbage")
