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
    (False, "datacenter", "unknown"), (False, "hosting", "unknown"), (None, "cdn", "unknown"),
])
def test_net_class(is_mobile, ct, exp):
    assert D._net_class(is_mobile, ct) == exp


def test_net_class_hosting_flag_and_why():
    # Cloudflare за CDN: connection_type может быть 'residential', но is_hosting=true
    assert D._net_class(False, "residential", hosting=True) == "unknown"
    assert D._unknown_why(False, False) == "no_conn"
    assert D._unknown_why(True, False) == "no_meta"
    assert D._unknown_why(True, True) == "cdn"
    assert D._unknown_why(False, False, via_cdn=True) == "cdn"


def test_inbound_behind_cdn_and_local_ip():
    def ss(net, sec):
        return {"tag": "x", "streamSettings": {"network": net, "security": sec}}
    assert D._inbound_behind_cdn(ss("xhttp", "none"))          # Moscow CDN: xhttp без TLS за прокси
    assert not D._inbound_behind_cdn(ss("ws", "tls"))          # ws+TLS напрямую в интернет — не CDN
    xff = ss("ws", "tls")
    xff["streamSettings"]["sockopt"] = {"trustedXForwardedFor": ["X-Forwarded-For"]}
    assert D._inbound_behind_cdn(xff)                          # явно доверяет заголовкам CDN
    assert not D._inbound_behind_cdn(ss("xhttp", "reality"))   # Reality через CDN не ходит
    assert not D._inbound_behind_cdn(ss("tcp", "reality"))
    assert not D._inbound_behind_cdn({"tag": "hy2", "streamSettings": {"network": "hysteria", "security": "tls"}})
    assert D._cdn_tags({"p": {"cdn_inbounds": ["a"]}, "q": {}}) == {"a"}
    assert D._is_local_ip("127.0.0.1") and D._is_local_ip("10.9.0.5") and not D._is_local_ip("31.173.85.177")
    assert not D._is_local_ip(None)


def test_cdn_is_own_group():
    assert "cdn" in D.GROUPS
    src = open(D.__file__, encoding="utf-8").read()
    assert 'cls[str(r["id"])] = "cdn"' in src


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


# ── каскад: матчинг «аутбаунд → наша нода» по строке и по IP (0.18.0) ──

def test_norm_host_and_ip_literal():
    assert D._norm_host(" Fra-01.Tusi.UK. ") == "fra-01.tusi.uk"
    assert D._norm_host("[2a01:db8::1]") == "2a01:db8::1"
    assert D._ip_literal("87.251.86.174") == "87.251.86.174"
    assert D._ip_literal("2A01:DB8::1") == "2a01:db8::1"
    assert D._ip_literal("fra-01.tusi.uk") is None
    assert D._ip_literal("") is None


def test_cascade_target_string_ip_and_self():
    a2u = {"fl.mikelfrost.ru": "hel", "87.251.86.174": "fra", "5.42.120.152": "mow"}
    resolved = {"fra-01.tusi.uk": frozenset({"87.251.86.174"}), "elsewhere.example": frozenset({"9.9.9.9"})}
    # домен = домен
    assert D._cascade_target("FL.mikelfrost.ru", "mow", a2u, resolved) == "hel"
    # аутбаунд доменом, нода в панели IP — совпадение через резолв
    assert D._cascade_target("fra-01.tusi.uk", "mow", a2u, resolved) == "fra"
    # чужой сервер — не каскад
    assert D._cascade_target("elsewhere.example", "mow", a2u, resolved) is None
    assert D._cascade_target("unresolved.example", "mow", a2u, resolved) is None
    # на саму себя — не каскад
    assert D._cascade_target("5.42.120.152", "mow", a2u, resolved) is None
    assert D._cascade_target(None, "mow", a2u, resolved) is None


async def test_resolve_hosts_uses_cache_and_survives_failures(monkeypatch):
    import asyncio
    import socket

    calls = []

    class Loop:
        async def getaddrinfo(self, host, port, type=None):
            calls.append(host)
            if host == "boom.example":
                raise socket.gaierror("nope")
            if host == "slow.example":
                await asyncio.sleep(5)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("87.251.86.174", 0)),
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2a01:db8::1", 0, 0, 0))]

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: Loop())
    monkeypatch.setattr(D, "RESOLVE_TIMEOUT_S", 0.05)
    D._resolve_cache.clear()

    out = await D._resolve_hosts(["Fra-01.tusi.uk", "87.251.86.174", "boom.example", "slow.example", "", None])
    assert out["fra-01.tusi.uk"] == frozenset({"87.251.86.174", "2a01:db8::1"})
    assert out["87.251.86.174"] == frozenset({"87.251.86.174"})   # литерал — без DNS
    assert out["boom.example"] == frozenset() and out["slow.example"] == frozenset()
    assert sorted(calls) == ["boom.example", "fra-01.tusi.uk", "slow.example"]

    calls.clear()
    out2 = await D._resolve_hosts(["fra-01.tusi.uk", "boom.example"])
    assert out2["fra-01.tusi.uk"] == out["fra-01.tusi.uk"] and calls == []   # оба из кэша (неудача — тоже, на короткий срок)
    D._resolve_cache.clear()


def test_module_js_cascade_is_a_hop_column_not_moved_nodes():
    js = MODULE_JS
    # колонка «Каскад» — карточки-прыжки, ноды в свой столбец не переселяются
    assert "function cascadeHops" in js and "function drawHopCard" in js and "cascadeHops(d, nodes)" in js
    assert "cascX" not in js and "cascNodes" not in js and "mainNodes" not in js and "cascadeArcs" not in js
    assert "function indexCascades" in js and "tipCascTo" in js and "tipCascFrom" in js and "lgCasc" in js and "hopFrom" in js
    # цвет каскада не совпадает с янтарным цветом линий группы «Через CDN»
    assert ".lf-casc{" in js and "hsl(38" not in js.split(".lf-casc{", 1)[1].split("}", 1)[0]
    # цепочка на чужой сервер подписывается адресом назначения
    assert "sk.kind === 'chain' && sk.addr" in js


def test_module_js_panel_modes():
    js = MODULE_JS
    # два режима списка «кто на ноде»: шторка поверх схемы и «рядом» с замком масштаба
    assert 'data-panel="over"' in js and 'data-panel="side"' in js and "panel: 'side', panelChosen: false" in js
    assert "if (!prefs.panelChosen) prefs.panel = 'side'" in js and "prefs.panelChosen = true" in js
    assert "function applyPanelMode" in js and "function settleSelected" in js and "function lockFit" in js
    assert ".lf-body.lf-over .lf-panel.open{position:absolute" in js
    assert "var locked = fitLock && panel" in js


def test_module_js_drag_and_card_lists():
    js = MODULE_JS
    # перетаскивание карточек: сдвиги в prefs.pos, кнопка сброса, рисование с учётом сдвига
    assert "pos: {}, posGrid: {}" in js and "function posOf" in js and "lf-posreset" in js and "posMap()[down.card]" in js
    assert "function placer(pos, reach, minY)" in js and "user-select:none" in js
    # «колонки»: та же колонка «Каскад» с прыжками, коридорных линий больше нет
    grid = js.split("function renderGrid")[1].split("function ensureStyle")[0]
    assert "cascadeHops(d, nodes)" in grid and "drawHopCard(h, pos['h:' + h.uuid])" in grid and "corr" not in grid
    # списки по клику на прыжок каскада и выход
    assert "'/cascade/' + id + '/users'" in js and "'/exit/' + id + '/users'" in js
    assert 'class="lf-hop" data-hop=' in js and 'class="lf-sink" data-sink=' in js
    assert ".lf-node, .lf-hop, .lf-sink" in js and "pByNodes" in js
    # переключатель списка не пересекается по классу с подсказкой внутри панели
    assert "'.lf-pm'" in js and "class=\"lf-pm\"" in js
    assert ".lf-body.lf-over{position:relative;flex-direction:column;align-items:stretch}" in js


async def test_cascade_and_exit_users_shape(monkeypatch):
    # collect() и poller подменяем: интересует только выбор нод и форма ответа
    nodes = [
        {"uuid": "mow", "name": "MOW-01", "cascades": ["hel", "fra"], "sinks": ["DIRECT"]},
        {"uuid": "hel", "name": "HEL-02", "cascades": [], "sinks": ["DIRECT", "warp-out"]},
        {"uuid": "fra", "name": "FRA-01", "cascades": [], "sinks": ["DIRECT"]},
    ]
    sinks = [{"tag": "DIRECT", "title": "Интернет", "kind": "internet"}, {"tag": "warp-out", "title": "warp-out", "kind": "internet"}]

    async def fake_collect(ctx):
        return {"nodes": nodes, "sinks": sinks}

    seen = {}

    async def fake_nodes_users(ctx, node_uuids, payload):
        seen["uuids"] = set(node_uuids)
        payload.update(users=[], count=0, source="panel-live")
        return payload

    monkeypatch.setattr(D, "collect", fake_collect)
    monkeypatch.setattr(D, "_nodes_users", fake_nodes_users)

    out = await D.cascade_users(None, "hel")
    assert out["kind"] == "cascade" and out["target"] == {"uuid": "hel", "name": "HEL-02"}
    assert out["nodes"] == ["MOW-01"] and out["by_nodes"] is True and seen["uuids"] == {"mow"}
    assert await D.cascade_users(None, "nope") is None

    out = await D.exit_users(None, "warp-out")
    assert out["kind"] == "exit" and out["sink"]["tag"] == "warp-out" and out["nodes"] == ["HEL-02"] and seen["uuids"] == {"hel"}
    out = await D.exit_users(None, "DIRECT")
    assert seen["uuids"] == {"mow", "hel", "fra"}
    assert await D.exit_users(None, "ghost") is None


async def test_profiles_expand_snippets(fake_panel):
    class Panel(_FakePanel):
        async def get_snippets(self):
            return {"response": {"total": 2, "snippets": [
                {"name": "warp", "snippet": [{"tag": "warp-out", "protocol": "freedom", "settings": {}}]},
                {"name": "casc", "snippet": {"tag": "casc-de", "protocol": "vless", "settings": {"vnext": [{"address": "fra-01.tusi.uk"}]}}},
                {"name": "broken", "snippet": "not a list"},
                "junk",
            ]}}
    fake_panel["api"] = Panel({"response": {"configProfiles": [
        {"uuid": "p1", "name": "with-snippets", "config": {"outbounds": [
            {"tag": "DIRECT", "protocol": "freedom"},
            {"snippet": "warp"},
            {"snippet": "casc"},
            {"snippet": "unknown-name"},
            {"snippet": "broken"},
            {"tag": "BLOCK", "protocol": "blackhole"},
        ]}},
    ]}})
    out = await D._profiles_by_uuid(_Logger())
    tags = [o["tag"] for o in out["p1"]["outbounds"]]
    assert tags == ["DIRECT", "warp-out", "casc-de", "BLOCK"]
    assert [o["addr"] for o in out["p1"]["outbounds"] if o["tag"] == "casc-de"] == ["fra-01.tusi.uk"]


async def test_profiles_without_snippets_api(fake_panel):
    # старый клиент без get_snippets или упавший запрос — ссылки просто пропускаются
    fake_panel["api"] = _FakePanel({"response": {"configProfiles": [
        {"uuid": "p1", "name": "x", "config": {"outbounds": [{"tag": "DIRECT", "protocol": "freedom"}, {"snippet": "warp"}]}},
    ]}})
    out = await D._profiles_by_uuid(_Logger())
    assert [o["tag"] for o in out["p1"]["outbounds"]] == ["DIRECT"]

    class Boom(_FakePanel):
        async def get_snippets(self):
            raise RuntimeError("x")
    fake_panel["api"] = Boom({"response": {"configProfiles": [
        {"uuid": "p1", "name": "x", "config": {"outbounds": [{"snippet": "warp"}, {"tag": "BLOCK", "protocol": "blackhole"}]}},
    ]}})
    out = await D._profiles_by_uuid(_Logger())
    assert [o["tag"] for o in out["p1"]["outbounds"]] == ["BLOCK"]
