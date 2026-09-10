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
    with open(D.__file__, encoding="utf-8") as fh:
        src = fh.read()
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
    assert D._norm_host(" Node-A.Example.TEST. ") == "node-a.example.test"
    assert D._norm_host("[2a01:db8::1]") == "2a01:db8::1"
    assert D._ip_literal("203.0.113.10") == "203.0.113.10"
    assert D._ip_literal("2A01:DB8::1") == "2a01:db8::1"
    assert D._ip_literal("node-a.example.test") is None
    assert D._ip_literal("") is None


def test_cascade_target_string_ip_and_self():
    a2u = {"node-b.example.test": "nb", "203.0.113.10": "na", "198.51.100.5": "src"}
    resolved = {"node-a.example.test": frozenset({"203.0.113.10"}), "elsewhere.example": frozenset({"9.9.9.9"})}
    # домен = домен
    assert D._cascade_target("NODE-B.example.test", "src", a2u, resolved) == "nb"
    # аутбаунд доменом, нода в панели IP — совпадение через резолв
    assert D._cascade_target("node-a.example.test", "src", a2u, resolved) == "na"
    # чужой сервер — не каскад
    assert D._cascade_target("elsewhere.example", "src", a2u, resolved) is None
    assert D._cascade_target("unresolved.example", "src", a2u, resolved) is None
    # на саму себя — не каскад
    assert D._cascade_target("198.51.100.5", "src", a2u, resolved) is None
    assert D._cascade_target(None, "src", a2u, resolved) is None


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
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0)),
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2a01:db8::1", 0, 0, 0))]

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: Loop())
    monkeypatch.setattr(D, "RESOLVE_TIMEOUT_S", 0.05)
    D._resolve_cache.clear()

    out = await D._resolve_hosts(["Node-a.example.test", "203.0.113.10", "boom.example", "slow.example", "", None])
    assert out["node-a.example.test"] == frozenset({"203.0.113.10", "2a01:db8::1"})
    assert out["203.0.113.10"] == frozenset({"203.0.113.10"})   # литерал — без DNS
    assert out["boom.example"] == frozenset() and out["slow.example"] == frozenset()
    assert sorted(calls) == ["boom.example", "node-a.example.test", "slow.example"]

    calls.clear()
    out2 = await D._resolve_hosts(["node-a.example.test", "boom.example"])
    assert out2["node-a.example.test"] == out["node-a.example.test"] and calls == []   # оба из кэша (неудача — тоже, на короткий срок)
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
    assert "'/cascade/' + id + '/users'" in js and "'/exit/users?tag=' + id" in js
    assert 'class="lf-hop" data-hop=' in js and 'class="lf-sink" data-sink=' in js
    assert ".lf-node, .lf-hop, .lf-sink" in js and "pByNodes" in js
    # переключатель списка не пересекается по классу с подсказкой внутри панели
    assert "'.lf-pm'" in js and "class=\"lf-pm\"" in js
    assert ".lf-body.lf-over{position:relative;flex-direction:column;align-items:stretch}" in js


async def test_cascade_and_exit_users_shape(monkeypatch):
    # collect() и poller подменяем: интересует только выбор нод и форма ответа
    nodes = [
        {"uuid": "src", "name": "node-src", "cascades": ["nb", "na"], "sinks": ["DIRECT"]},
        {"uuid": "nb", "name": "node-b", "cascades": [], "sinks": ["DIRECT", "warp-out"]},
        {"uuid": "na", "name": "node-a", "cascades": [], "sinks": ["DIRECT"]},
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

    out = await D.cascade_users(None, "nb")
    assert out["kind"] == "cascade" and out["target"] == {"uuid": "nb", "name": "node-b"}
    assert out["nodes"] == ["node-src"] and out["by_nodes"] is True and seen["uuids"] == {"src"}
    assert await D.cascade_users(None, "nope") is None

    out = await D.exit_users(None, "warp-out")
    assert out["kind"] == "exit" and out["sink"]["tag"] == "warp-out" and out["nodes"] == ["node-b"] and seen["uuids"] == {"nb"}
    out = await D.exit_users(None, "DIRECT")
    assert seen["uuids"] == {"src", "nb", "na"}
    assert await D.exit_users(None, "ghost") is None


async def test_profiles_expand_snippets(fake_panel):
    class Panel(_FakePanel):
        async def get_snippets(self):
            return {"response": {"total": 2, "snippets": [
                {"name": "warp", "snippet": [{"tag": "warp-out", "protocol": "freedom", "settings": {}}]},
                {"name": "casc", "snippet": {"tag": "casc-de", "protocol": "vless", "settings": {"vnext": [{"address": "node-a.example.test"}]}}},
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
    assert [o["addr"] for o in out["p1"]["outbounds"] if o["tag"] == "casc-de"] == ["node-a.example.test"]


async def test_profiles_without_snippets_api_marks_unresolved(fake_panel):
    # старый клиент без get_snippets: раскрыть нечем — ссылка помечена неразрешённой, DIRECT не выдумывается
    fake_panel["api"] = _FakePanel({"response": {"configProfiles": [
        {"uuid": "p1", "name": "x", "config": {"outbounds": [{"tag": "DIRECT", "protocol": "freedom"}, {"snippet": "warp"}]}},
    ]}})
    out = await D._profiles_by_uuid(_Logger())
    assert [o["tag"] for o in out["p1"]["outbounds"]] == ["DIRECT"]
    assert out["p1"]["snippets_unresolved"] == ["warp"] and out["p1"]["has_outbounds"] is True


async def test_profiles_snippet_request_failure_means_profiles_not_loaded(fake_panel):
    # запрос сниппетов упал, а профили на них ссылаются — набор не загружен (None), а не «пусто и успешно»
    class Boom(_FakePanel):
        async def get_snippets(self):
            raise RuntimeError("x")
    fake_panel["api"] = Boom({"response": {"configProfiles": [
        {"uuid": "p1", "name": "x", "config": {"outbounds": [{"snippet": "warp"}, {"tag": "BLOCK", "protocol": "blackhole"}]}},
    ]}})
    assert await D._profiles_by_uuid(_Logger()) is None
    # без ссылок сниппеты не нужны — сбой их запроса ни на что не влияет
    fake_panel["api"] = Boom({"response": {"configProfiles": [
        {"uuid": "p2", "name": "y", "config": {"outbounds": [{"tag": "DIRECT", "protocol": "freedom"}]}},
    ]}})
    out = await D._profiles_by_uuid(_Logger())
    assert [o["tag"] for o in out["p2"]["outbounds"]] == ["DIRECT"] and out["p2"]["snippets_unresolved"] == []


def _panel_with_snippets(profiles, snippets):
    class Panel(_FakePanel):
        async def get_snippets(self):
            if isinstance(snippets, Exception):
                raise snippets
            return {"response": {"total": len(snippets), "snippets": snippets}}
    return Panel({"response": {"configProfiles": profiles}})


_WARP_ONLY = [{"uuid": "p1", "name": "warp-only", "config": {"outbounds": [{"snippet": "warp"}]}}]
_WARP_SNIPPET = [{"name": "warp", "snippet": [{"tag": "warp-out", "protocol": "freedom", "settings": {}}]}]


async def test_snippets_success_failure_recovery_keeps_last_good(fake_panel, monkeypatch):
    # профиль из одного WARP-сниппета: успех → сбой сниппетов после истечения кэша → восстановление
    monkeypatch.setattr(D, "PROFILES_TTL_S", 0.0)
    D._profiles_cache.update(ts=0.0, data=None, stale=False, last_log=0.0)
    fake_panel["api"] = _panel_with_snippets(_WARP_ONLY, _WARP_SNIPPET)
    data, stale = await D._profiles_cached(_Logger())
    assert stale is False and [o["tag"] for o in data["p1"]["outbounds"]] == ["warp-out"]

    fake_panel["api"] = _panel_with_snippets(_WARP_ONLY, RuntimeError("snippets down"))
    data2, stale2 = await D._profiles_cached(_Logger())
    assert stale2 is True and [o["tag"] for o in data2["p1"]["outbounds"]] == ["warp-out"]   # последний удачный, помечен stale
    assert D._effective_outbounds(data2["p1"], True) == data2["p1"]["outbounds"]            # и никакого DIRECT

    fake_panel["api"] = _panel_with_snippets(_WARP_ONLY, _WARP_SNIPPET)
    data3, stale3 = await D._profiles_cached(_Logger())
    assert stale3 is False and [o["tag"] for o in data3["p1"]["outbounds"]] == ["warp-out"]


async def test_snippets_cold_start_failure_means_config_unavailable(fake_panel, monkeypatch):
    monkeypatch.setattr(D, "PROFILES_TTL_S", 0.0)
    D._profiles_cache.update(ts=0.0, data=None, stale=False, last_log=0.0)
    fake_panel["api"] = _panel_with_snippets(_WARP_ONLY, RuntimeError("snippets down"))
    data, stale = await D._profiles_cached(_Logger())
    assert data is None and stale is False          # холодный старт: конфигурации нет, UI покажет «недоступна»
    assert D._effective_outbounds({}, False) == []   # выходов не рисуем, DIRECT не выдумываем


async def test_snippets_empty_success_is_unresolved_not_direct(fake_panel):
    # успешный пустой ответ сниппетов ≠ ошибка: профиль загружен, ссылка неразрешена, выходы пусты
    fake_panel["api"] = _panel_with_snippets(_WARP_ONLY, [])
    out = await D._profiles_by_uuid(_Logger())
    assert out["p1"]["outbounds"] == [] and out["p1"]["snippets_unresolved"] == ["warp"]
    assert D._effective_outbounds(out["p1"], True) == []


async def test_snippets_mixed_plain_and_snippet_outbounds(fake_panel):
    profiles = [{"uuid": "p1", "name": "mixed", "config": {"outbounds": [
        {"tag": "DIRECT", "protocol": "freedom"}, {"snippet": "warp"}, {"snippet": "missing"}, {"tag": "BLOCK", "protocol": "blackhole"},
    ]}}]
    fake_panel["api"] = _panel_with_snippets(profiles, _WARP_SNIPPET)
    out = await D._profiles_by_uuid(_Logger())
    assert [o["tag"] for o in out["p1"]["outbounds"]] == ["DIRECT", "warp-out", "BLOCK"]
    assert out["p1"]["snippets_unresolved"] == ["missing"]


def test_effective_outbounds_rules():
    direct = [{"tag": "DIRECT", "protocol": "freedom"}]
    assert D._effective_outbounds({}, False) == []                                   # профили не получены
    assert D._effective_outbounds({}, True) == direct                                # у ноды нет профиля
    assert D._effective_outbounds({"has_outbounds": False, "outbounds": []}, True) == direct   # профиль без выходов
    assert D._effective_outbounds({"has_outbounds": True, "outbounds": []}, True) == []        # выходы были, ссылка не раскрылась
    assert D._effective_outbounds({"has_outbounds": True, "outbounds": [{"tag": "x"}]}, True) == [{"tag": "x"}]
    assert D._expand_snippets([{"snippet": "a"}, {"tag": "t"}], {}) == ([{"tag": "t"}], ["a"])


# ── маршруты списков: тег выхода со спецсимволами ──

def _app_with_router(monkeypatch, seen):
    import sys
    import types

    from fastapi import FastAPI

    class AdminUser:  # noqa: D401 — заглушка типа
        pass

    def require_permission(*_a, **_k):
        async def dep():
            return AdminUser()
        return dep

    api = types.ModuleType("web.backend.core.plugin_api")
    api.auth_deps = lambda: (AdminUser, require_permission)
    api.panel_api = lambda: None
    for name in ("web", "web.backend", "web.backend.core"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "web.backend.core.plugin_api", api)

    async def fake_exit_users(ctx, tag):
        seen.append(tag)
        return None if tag == "ghost" else {"kind": "exit", "sink": {"tag": tag, "kind": "internet"}, "nodes": [], "by_nodes": True, "users": [], "count": 0}

    monkeypatch.setattr(D, "exit_users", fake_exit_users)
    from rwa_live_flow.routes import build_router
    app = FastAPI()
    app.include_router(build_router(types.SimpleNamespace(logger=_Logger(), db=None)))
    return app


def test_exit_users_route_accepts_special_tags(monkeypatch):
    from fastapi.testclient import TestClient
    from urllib.parse import quote

    seen: list = []
    client = TestClient(_app_with_router(monkeypatch, seen))
    for tag in ["warp-out", 'exit"quoted', "back\\slash", "proxy/us", "узел-1"]:
        r = client.get("/exit/users", params={"tag": tag})
        assert r.status_code == 200, (tag, r.text)
        assert r.headers["cache-control"] == "private, no-store"
        assert r.json()["sink"]["tag"] == tag
    assert seen == ["warp-out", 'exit"quoted', "back\\slash", "proxy/us", "узел-1"]
    # прежний маршрут: тег без «/» работает, с «/» — 404 маршрутизации (поэтому UI ходит через ?tag=)
    assert client.get("/exit/warp-out/users").status_code == 200
    assert client.get("/exit/" + quote("proxy/us", safe="") + "/users").status_code == 404
    assert client.get("/exit/users", params={"tag": "ghost"}).status_code == 404
    assert client.get("/exit/users").status_code == 422
    assert client.get("/exit/users", params={"tag": ""}).status_code == 422


def test_module_js_special_tags_and_config_notes():
    js = MODULE_JS
    # выбор карточки — сравнением атрибута, а не подстановкой значения в селектор
    assert "function byAttr(view, selector, attr, value)" in js and "byAttr(view, '.lf-sink', 'data-sink', id)" in js
    assert "querySelector('.lf-sink[data-sink=" not in js
    # тег выхода уходит query-параметром
    assert "'/exit/users?tag=' + id" in js and "'/exit/' + id + '/users'" not in js
    # состояние конфигурации выходов видно в легенде
    assert "profilesStale" in js and "snippetsUnresolved" in js and "notes.join(' · ')" in js
    # колонка групп — единым блоком, высота холста учитывает её нижний край всегда
    assert "var groupTop = Math.max(TOP, centerY - colH / 2);" in js and "H = Math.max(H, groupTop + colH + 34, reach.y + 34);" in js
    assert "if (hasPos()) { W = Math.max" not in js
