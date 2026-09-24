"""Тесты разбора профилей, классификации сети и экранирования в UI-модуле."""
from __future__ import annotations

import re

import pytest

from rwa_live_flow import data as D
from rwa_live_flow import metrics as M
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
    assert "profilesStale" in js and "snippetsUnresolved" in js and "configNotes(d).join(' · ')" in js
    # колонка групп — единым блоком, высота холста учитывает её нижний край всегда
    assert "var groupTop = Math.max(TOP, centerY - colH / 2);" in js and "H = Math.max(H, groupTop + colH + 34, reach.y + 34);" in js
    assert "if (hasPos()) { W = Math.max" not in js


# ── сниппеты через computed-config панели (0.17.3) ──

def _panel_with_computed(profiles, computed, snippets=None, calls=None):
    class Panel(_FakePanel):
        async def get_config_profile_computed(self, uuid):
            if calls is not None:
                calls.append(uuid)
            v = computed[uuid] if uuid in computed else computed.get("*")
            if isinstance(v, Exception):
                raise v
            return {"response": {"uuid": uuid, "config": v}}
    if snippets is not None:
        async def get_snippets(self):
            return {"response": {"total": len(snippets), "snippets": snippets}}
        Panel.get_snippets = get_snippets
    return Panel({"response": {"configProfiles": profiles}})


_MIXED = [
    {"uuid": "p1", "name": "with-refs", "config": {"outbounds": [{"tag": "DIRECT", "protocol": "freedom"}, {"snippet": "warp"}], "routing": {"rules": [{"snippet": "block-private"}]}}},
    {"uuid": "p2", "name": "plain", "config": {"outbounds": [{"tag": "DIRECT", "protocol": "freedom"}, {"tag": "BLOCK", "protocol": "blackhole"}]}},
]
_P1_COMPUTED = {"outbounds": [{"tag": "DIRECT", "protocol": "freedom"}, {"tag": "warp-out", "protocol": "freedom", "settings": {}}, {"tag": "psiphon-out", "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1"}]}}], "routing": {"rules": []}}


async def test_computed_config_expands_only_profiles_with_refs(fake_panel):
    calls: list = []
    fake_panel["api"] = _panel_with_computed(_MIXED, {"p1": _P1_COMPUTED}, calls=calls)
    out = await D._profiles_by_uuid(_Logger())
    assert calls == ["p1"]                                          # обычный профиль — без лишнего запроса
    assert [o["tag"] for o in out["p1"]["outbounds"]] == ["DIRECT", "warp-out", "psiphon-out"]
    assert out["p1"]["snippets_unresolved"] == [] and out["p1"]["has_outbounds"] is True
    assert [o["tag"] for o in out["p2"]["outbounds"]] == ["DIRECT", "BLOCK"]
    assert [o["addr"] for o in out["p1"]["outbounds"] if o["tag"] == "psiphon-out"] == ["127.0.0.1"]


async def test_computed_config_accepts_json_string(fake_panel):
    import json as _json
    fake_panel["api"] = _panel_with_computed(_MIXED, {"p1": _json.dumps(_P1_COMPUTED)})
    out = await D._profiles_by_uuid(_Logger())
    assert [o["tag"] for o in out["p1"]["outbounds"]] == ["DIRECT", "warp-out", "psiphon-out"]


async def test_computed_config_failure_keeps_last_good(fake_panel, monkeypatch):
    monkeypatch.setattr(D, "PROFILES_TTL_S", 0.0)
    D._profiles_cache.update(ts=0.0, data=None, stale=False, last_log=0.0)
    fake_panel["api"] = _panel_with_computed(_MIXED, {"p1": _P1_COMPUTED})
    data, stale = await D._profiles_cached(_Logger())
    assert stale is False and "warp-out" in [o["tag"] for o in data["p1"]["outbounds"]]

    fake_panel["api"] = _panel_with_computed(_MIXED, {"p1": RuntimeError("panel 502")})
    data2, stale2 = await D._profiles_cached(_Logger())
    assert stale2 is True and "warp-out" in [o["tag"] for o in data2["p1"]["outbounds"]]   # последний удачный, помечен stale

    fake_panel["api"] = _panel_with_computed(_MIXED, {"p1": "{not json"})               # кривой ответ = сбой
    data3, stale3 = await D._profiles_cached(_Logger())
    assert stale3 is True and "warp-out" in [o["tag"] for o in data3["p1"]["outbounds"]]

    fake_panel["api"] = _panel_with_computed(_MIXED, {"p1": _P1_COMPUTED})
    data4, stale4 = await D._profiles_cached(_Logger())
    assert stale4 is False


async def test_computed_config_cold_start_failure(fake_panel, monkeypatch):
    monkeypatch.setattr(D, "PROFILES_TTL_S", 0.0)
    D._profiles_cache.update(ts=0.0, data=None, stale=False, last_log=0.0)
    fake_panel["api"] = _panel_with_computed(_MIXED, {"p1": RuntimeError("panel down")})
    assert await D._profiles_cached(_Logger()) == (None, False)


async def test_computed_config_residual_ref_is_unresolved(fake_panel):
    fake_panel["api"] = _panel_with_computed(_MIXED, {"p1": {"outbounds": [{"tag": "DIRECT", "protocol": "freedom"}, {"snippet": "ghost"}]}})
    out = await D._profiles_by_uuid(_Logger())
    assert [o["tag"] for o in out["p1"]["outbounds"]] == ["DIRECT"] and out["p1"]["snippets_unresolved"] == ["ghost"]


async def test_snippets_fallback_when_client_has_no_computed_method(fake_panel):
    # старая админка: метода computed-config нет, но есть get_snippets — раскрываем по именам
    fake_panel["api"] = _panel_with_snippets(_MIXED, [{"name": "warp", "snippet": [{"tag": "warp-out", "protocol": "freedom"}]}])
    assert not hasattr(fake_panel["api"], "get_config_profile_computed")
    out = await D._profiles_by_uuid(_Logger())
    assert [o["tag"] for o in out["p1"]["outbounds"]] == ["DIRECT", "warp-out"]


# ── состояние агента ноды ──────────────────────────────────────────
@pytest.mark.parametrize("m_age, users, seen, exp", [
    (None, 5, True, "none"),              # метрик не было вовсе — агента нет
    (900.0, 5, True, "none"),             # метрики протухли — агент умер
    (10.0, 5, True, "log"),              # разбор лога приходит — всё работает
    (10.0, 0, True, "log"),
    (10.0, 5, False, "metrics_only"),      # агент жив, люди есть, а строк нет
    (10.0, 0, False, "idle"),              # нода пуста — судить не о чем
])
def test_agent_state(m_age, users, seen, exp):
    assert D._agent_state(m_age, users, seen) == exp


async def test_log_age_cache_survives_db_failure(monkeypatch):
    class Ctx:
        logger = _Logger()

        class db:
            calls = 0

            @staticmethod
            async def fetch(*a, **k):
                Ctx.db.calls += 1
                if Ctx.db.calls == 1:
                    return [{"nu": "n1", "uid": "7"}]
                raise RuntimeError("db down")

    D._agent_cache.update(ts=0.0, map=None)
    assert await D._log_seen_by_node(Ctx) == {"n1": {"7"}}
    D._agent_cache["ts"] = 0.0                       # просрочили кэш
    assert await D._log_seen_by_node(Ctx) == {"n1": {"7"}}  # сбой — отдаём прошлое
    assert D._agent_cache["ts"] > 0.0                # и всё равно ждём TTL, а не долбим базу


# ── метрики нод: строки панели, окно, квантование ──────────────────
def test_parse_iec_matches_panel_format():
    # значения — из прогона самой панели (prettyBytesUtil поверх xbytes, IEC)
    assert M.parse_iec("0") == 0                      # ровный ноль — без единицы
    assert M.parse_iec("1.00 B") == 1
    assert M.parse_iec("1.00 MiB") == 1048576
    assert M.parse_iec("953.67 MiB") == 999995473     # это панельные 1e9 байт
    assert M.parse_iec("5.50 TiB") == 6047313952768
    for junk in (None, "", "junk", "12,3 GiB", "12 GB", -5):
        assert M.parse_iec(junk) is None              # неизвестно, а не ноль
    assert M.quantum("1.00 GiB") == 1073741824 // 100
    assert M.quantum("0") == 1


def _poller_with(snaps, age=0.0):
    """Окно из снимков; время сдвигается так, что последний снят ``age`` секунд назад."""
    import time
    from collections import deque
    shift = time.time() - age - max(s[0] for s in snaps)
    p = M.NodeMetricsPoller()
    p._win["n1"] = deque([(ts + shift, v, st) for ts, v, st in snaps], maxlen=M.SNAPSHOTS)
    return p


def _snap(ts, vals, step):
    kv = {("out", t): v for t, v in vals.items()}
    return (ts, kv, {k: step for k in kv})


def test_shares_split_by_branch():
    step = M.quantum("1.00 GiB")
    p = _poller_with([_snap(0.0, {"DIRECT": 0, "WARP": 0}, step),
                      _snap(600.0, {"DIRECT": 80 * step, "WARP": 20 * step}, step)])
    r = p.shares("n1")
    assert round(r["shares"]["DIRECT"], 2) == 0.8
    assert round(r["shares"]["WARP"], 2) == 0.2
    assert r["window_s"] == 600.0


@pytest.mark.parametrize("snaps", [
    # один снимок — делить нечего
    [_snap(0.0, {"DIRECT": 0}, 1)],
    # окно короче MIN_WINDOW_S — доли ещё шумные
    [_snap(0.0, {"DIRECT": 0}, 1), _snap(30.0, {"DIRECT": 10 ** 9}, 1)],
    # дельта меньше двух шагов квантования: на TiB это штатное состояние,
    # и «нет измерений» честнее застывших долей
    [_snap(0.0, {"DIRECT": 0, "WARP": 0}, M.quantum("1.00 TiB")),
     _snap(600.0, {"DIRECT": M.quantum("1.00 TiB"), "WARP": 0}, M.quantum("1.00 TiB"))],
])
def test_shares_returns_none_when_nothing_to_measure(snaps):
    assert _poller_with(snaps).shares("n1") is None


def test_shares_skip_branch_whose_counter_went_backwards():
    # рестарт remnawave-scheduler обнуляет счётчики: такая ветка выпадает
    # из окна целиком, а не даёт отрицательную долю
    step = M.quantum("1.00 MiB")
    p = _poller_with([_snap(0.0, {"DIRECT": 100 * step, "WARP": 0}, step),
                      _snap(600.0, {"DIRECT": 5 * step, "WARP": 40 * step}, step)])
    r = p.shares("n1")
    assert set(r["shares"]) == {"WARP"} and r["shares"]["WARP"] == 1.0


class _FakeMetricsApi:
    def __init__(self, payload):
        self.payload = payload

    async def get_nodes_metrics(self):
        return self.payload


async def test_metrics_tick_drops_service_tags(fake_panel):
    fake_panel["api"] = _FakeMetricsApi({"response": {"nodes": [{
        "nodeUuid": "n1",
        "inboundsStats": [{"tag": "REMNAWAVE_API_INBOUND", "upload": "1.00 MiB", "download": "0"}],
        "outboundsStats": [{"tag": "DIRECT", "upload": "1.00 GiB", "download": "2.00 GiB"},
                           {"tag": "RW_TB_OUTBOUND_BLOCK", "upload": "0", "download": "0"},
                           "junk"],
    }]}})
    p = M.NodeMetricsPoller()
    await p._tick_impl(_Logger())
    vals = p._win["n1"][-1][1]
    assert set(vals) == {("out", "DIRECT")}
    assert vals[("out", "DIRECT")] == M.parse_iec("1.00 GiB") + M.parse_iec("2.00 GiB")
    assert p.error is None


async def test_metrics_tick_distinguishes_empty_and_unsupported(fake_panel):
    fake_panel["api"] = _FakeMetricsApi({"response": {"nodes": []}})
    p = M.NodeMetricsPoller()
    await p._tick_impl(_Logger())
    assert p.error == "metrics_empty" and p.as_of is not None

    fake_panel["api"] = object()          # админка постарше, метода нет
    p2 = M.NodeMetricsPoller()
    await p2._tick_impl(_Logger())
    assert p2.error == "metrics_unsupported"


# ── фильтр списка по фактическому аутбаунду ────────────────────────────
def _payload(rows):
    return {"users": list(rows), "count": len(rows), "by_nodes": True, "nodes": ["n"]}


def test_by_outbound_filters_when_agents_report_tags():
    rows = [
        {"user": "a", "node_uuid": "n1", "outbound": ["casc-fi", "DIRECT"]},
        {"user": "b", "node_uuid": "n1", "outbound": ["DIRECT"]},
        {"user": "c", "node_uuid": "n1", "outbound": []},
    ]
    out = D._by_outbound(_payload(rows), ["casc-fi", "casc-lv"])
    assert [r["user"] for r in out["users"]] == ["a"]
    assert out["by_outbound"] is True and out["by_nodes"] is False and out["count"] == 1


def test_by_outbound_keeps_list_when_nobody_has_tags():
    # старые агенты поля не шлют: соврать «никого» хуже, чем отдать список по нодам
    rows = [{"user": "a", "node_uuid": "n1", "outbound": None},
            {"user": "b", "node_uuid": "n1", "outbound": []}]
    out = D._by_outbound(_payload(rows), ["casc-fi"])
    assert len(out["users"]) == 2 and out["by_nodes"] is True and "by_outbound" not in out


def test_by_outbound_without_tags_is_noop():
    rows = [{"user": "a", "node_uuid": "n1", "outbound": ["DIRECT"]}]
    assert D._by_outbound(_payload(rows), [])["users"] == rows


async def test_users_rows_carry_outbound_tags(monkeypatch):
    """Теги должны доезжать до строки ответа, а не только до SELECT."""
    from datetime import datetime, timezone

    now = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)

    class Ctx:
        logger = _Logger()

        class db:
            @staticmethod
            async def fetch(sql, *a):
                if "FROM users WHERE id" in sql:
                    return [{"id": 7, "uuid": "u-7"}]
                return [{
                    "user_uuid": "u-7", "ip_address": "1.2.3.4", "connected_at": now,
                    "inbound": "Estonia", "outbound": ["DIRECT", "warp-out"],
                    "asn": None, "asn_org": None, "country_code": None, "city": None,
                    "is_mobile": None, "is_hosting": None, "is_vpn": None, "is_proxy": None,
                }]

    class Poller:
        nodes = {"n1": {"name": "TLL-01"}}

        @staticmethod
        def user_bps(_):
            return None

    rows = await D._users_rows(Ctx, Poller, [("7", {"username": "kot", "online_at": now, "node_uuid": "n1"})], with_node=True)
    assert rows[0]["outbound"] == ["DIRECT", "warp-out"]
    assert D._by_outbound({"users": rows, "count": 1, "by_nodes": True}, ["warp-out"])["by_outbound"] is True


@pytest.mark.parametrize("raw, exp", [
    (["DIRECT", "warp-out"], ["DIRECT", "warp-out"]),      # декодер jsonb включён
    ('["DIRECT", "warp-out"]', ["DIRECT", "warp-out"]),    # ...и когда нет — та же строка
    ("[]", []),                                            # агент прислал, аутбаундов не было
    (None, None),                                          # старый агент поля не шлёт
    ("не json", None), ('{"a": 1}', None), (5, None),
])
def test_outbound_tags_accepts_both_jsonb_forms(raw, exp):
    assert D._outbound_tags(raw) == exp


# ── M2: снимки Connections API ─────────────────────────────────────────
from rwa_live_flow import connections as C  # noqa: E402


def test_job_result_shapes():
    ready = {"response": {"isCompleted": True, "result": {"success": True, "users": [
        {"userId": 7, "ips": [{"ip": "1.2.3.4", "lastSeen": "x"}, {"ip": "5.6.7.8"}]},
        {"userId": 9, "ips": []},          # за локальным прокси: xray 127.0.0.1 в карту не кладёт
        {"ips": [{"ip": "9.9.9.9"}]},      # без userId — мусор
    ]}}}
    assert C._job_result(ready) == {"7": ["1.2.3.4", "5.6.7.8"], "9": []}
    # нода не на связи: job завершился успешно, снимок пустой — это не ошибка
    assert C._job_result({"response": {"isCompleted": True, "result": {"success": False, "users": []}}}) == {}
    # ещё считается
    assert C._job_result({"response": {"isCompleted": False}}) is None
    assert C._job_result({}) is None and C._job_result(None) is None
    assert C._job_id({"response": {"jobId": "1"}}) == "1"
    assert C._job_id({"response": {}}) is None and C._job_id("мусор") is None


class _FakeConnApi:
    """Панель: POST отдаёт jobId, GET — готовый результат со второго раза."""

    def __init__(self):
        self.posts, self.gets = [], []

    async def fetch_users_ips_by_node(self, node_uuid):
        self.posts.append(node_uuid)
        return {"response": {"jobId": "job-" + node_uuid}}

    async def get_fetch_users_ips_result(self, job_id):
        self.gets.append(job_id)
        node = job_id.replace("job-", "")
        if len(self.gets) < 2:
            return {"response": {"isCompleted": False}}
        return {"response": {"isCompleted": True, "result": {
            "success": True, "nodeUuid": node, "users": [{"userId": 42, "ips": [{"ip": "203.0.113.7"}]}]}}}


async def test_sweep_is_a_state_machine_without_sleeping(fake_panel):
    api = _FakeConnApi()
    fake_panel["api"] = api
    p = C.ConnectionsPoller()
    nodes = {"n1": {"connected": True, "disabled": False},
             "n2": {"connected": False, "disabled": False}}   # отключённую не трогаем

    await p._tick_impl(nodes, _Logger())          # тик 1: только POST
    assert api.posts == ["n1"] and p.ips("n1") is None
    await p._tick_impl(nodes, _Logger())          # тик 2: job ещё считается
    assert p.ips("n1") is None and api.posts == ["n1"]
    await p._tick_impl(nodes, _Logger())          # тик 3: результат приехал
    assert p.ips("n1") == {"42": ["203.0.113.7"]}
    assert p.user_ip("n1", 42) == "203.0.113.7"
    assert p.user_ip("n1", 99) is None
    assert "n2" not in p._st                       # отключённую ноду не опрашивали


async def test_sweep_survives_dead_job_and_missing_method(fake_panel):
    class Boom:
        async def fetch_users_ips_by_node(self, node_uuid):
            raise RuntimeError("A011")

        async def get_fetch_users_ips_result(self, job_id):
            raise RuntimeError("A218")

    fake_panel["api"] = Boom()
    p = C.ConnectionsPoller()
    await p._tick_impl({"n1": {"connected": True, "disabled": False}}, _Logger())
    assert p._st["n1"]["phase"] == "idle" and p._st["n1"]["fails"] == 1
    assert p.error == "connections_unavailable"    # ни один запрос не прошёл — это видно в легенде

    fake_panel["api"] = object()                   # админка постарше — методов нет
    p2 = C.ConnectionsPoller()
    await p2._tick_impl({"n1": {"connected": True, "disabled": False}}, _Logger())
    assert p2.error == "connections_unsupported"


# ── свежесть: чему верим в состоянии агента ────────────────────────────
@pytest.mark.parametrize("agent, snap, exp", [
    ({"7"}, None, True),
    (set(), None, False),
    # 🔴 снимок панели НЕ участвует: node_uuid в user_connections ненадёжен,
    # сверка по нему объявляла сломанными исправные ноды (AMS-01, 12.09.2026)
    ({"13"}, {"7": ["1.1.1.1"]}, True),
    (set(), {"7": ["1.1.1.1"]}, False),
])
def test_log_alive_ignores_panel_snapshot(agent, snap, exp):
    assert D._log_alive(agent) is exp   # снимок в сигнатуре больше не принимается вовсе


async def test_classify_ignores_stale_agent_row(fake_panel, monkeypatch):
    import time
    from datetime import datetime, timezone

    """Тип сети не должен считаться по адресу, с которого человек уже ушёл."""
    from rwa_live_flow import connections as CC

    class Ctx:
        logger = _Logger()

        class db:
            @staticmethod
            async def fetch(sql, *a):
                if "FROM ip_metadata WHERE" in sql:      # запрос _panel_ips
                    return []                            # новый IP GeoIP ещё не знает
                return [{
                    "id": 7, "is_mobile": True, "connection_type": "mobile", "hosting": False,
                    "has_conn": True, "has_meta": True, "ip": "10.0.0.9", "inbound": "in",
                    "connected_at": datetime(2026, 9, 12, 10, 0, tzinfo=timezone.utc),
                }]

    # панель видит этого человека уже с другого адреса.
    # 203.0.113.0/24 тут не годится: ipaddress считает диапазоны для
    # документации приватными, и _is_local_ip отбросил бы адрес.
    CC.POLLER._st["n1"] = {"phase": "idle", "job": None, "ips": {"7": ["91.79.15.105"]},
                           "as_of": time.time(), "fails": 0}
    try:
        D._cls_cache.update(ts=0.0, map={})
        cls = await D._classify_users_db(Ctx, ["7"], {"7": "n1"})
        assert cls["7"] == "unknown"                     # не «мобильный» по старому IP
        assert D._cls_why["7"] == "no_meta"              # честная причина
    finally:
        CC.POLLER._st.pop("n1", None)


@pytest.mark.parametrize("ip, age_min, exp", [
    # адрес есть в снимке — строка актуальна независимо от возраста
    ("1.1.1.1", 600, False),
    # адреса нет, строка старше снимка — опровергнута
    ("2.2.2.2", 600, True),
    # 🔴 адреса нет, но строка МОЛОЖЕ снимка: человек только что сменил IP,
    # агент уже отчитался, а снимок отстал. Выбрасывать нельзя — потеряем
    # тег инбаунда и вместе с ним группу «Предположительно CDN».
    ("2.2.2.2", 0, False),
])
def test_row_outdated_respects_snapshot_age(ip, age_min, exp):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    snap_at = now - timedelta(minutes=1)
    connected_at = now - timedelta(minutes=age_min)
    assert D._row_outdated(ip, connected_at, {"1.1.1.1"}, snap_at) is exp


def test_row_outdated_without_snapshot_never_drops():
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    assert D._row_outdated("2.2.2.2", now, set(), now) is False      # снимка нет
    assert D._row_outdated("2.2.2.2", now, {"1.1.1.1"}, None) is False  # возраст неизвестен


# ── слепой инбаунд: Xray пишет всех как 127.0.0.1 ─────────────────────
def _ib(listen=None, network="xhttp", sockopt=None):
    ss = {"network": network, "security": "none"}
    if sockopt is not None:
        ss["sockopt"] = sockopt
    ib = {"tag": "t", "streamSettings": ss}
    if listen is not None:
        ib["listen"] = listen
    return ib


@pytest.mark.parametrize("ib, exp", [
    (_ib("127.0.0.1"), True),                                   # как во всех гайдах: слепой
    (_ib("/dev/shm/xray.sock"), True),                          # unix-сокет за прокси — тоже
    (_ib("127.0.0.1", sockopt={"trustedXForwardedFor": ["X-Forwarded-For"]}), False),
    (_ib("127.0.0.1", sockopt={"acceptProxyProtocol": True}), False),   # PROXY protocol видит адрес
    (_ib(None), False),                                         # наружу напрямую — адрес виден
    (_ib("0.0.0.0"), False),
    (_ib("127.0.0.1", network="tcp"), False),                   # reality/tcp — не HTTP-транспорт
])
def test_inbound_blind(ib, exp):
    assert D._inbound_blind(ib) is exp


# ── метка CDN владельцем в конфиге ─────────────────────────────────────
@pytest.mark.parametrize("ib, exp", [
    ({"tag": "x", "liveFlow": {"cdn": True}}, True),
    ({"tag": "x", "liveFlow": {"cdn": "true"}}, False),   # строка — не метка: без двусмысленностей
    ({"tag": "x", "liveFlow": {}}, False),
    ({"tag": "x", "liveFlow": True}, False),
    ({"tag": "x"}, False),
])
def test_inbound_declared_cdn(ib, exp):
    assert D._inbound_declared_cdn(ib) is exp


def test_declared_marks_switch_off_heuristic():
    heur = {"p": {"cdn_inbounds": ["guess-a", "guess-b"], "cdn_declared": []}}
    assert D._cdn_mode(heur) == "heuristic"
    assert D._cdn_tags(heur) == {"guess-a", "guess-b"}
    # владелец пометил один вход — угаданные больше не считаются CDN нигде
    decl = {"p": {"cdn_inbounds": ["guess-a", "guess-b"], "cdn_declared": ["Moscow CDN"]},
            "q": {"cdn_inbounds": ["guess-c"], "cdn_declared": []}}
    assert D._cdn_mode(decl) == "declared"
    assert D._cdn_tags(decl) == {"Moscow CDN"}
    assert D._cdn_mode(None) == "heuristic"


# ── 0.17.6: сбои источников не выдаются за данные ──────────────────────
def _live(n):
    return {f"n{i}": {"connected": True, "disabled": False} for i in range(n)}


class _Forbidden:
    """Токену админки не выдали права на connections: каждый запрос — 403."""

    def __init__(self):
        self.posts = 0

    async def fetch_users_ips_by_node(self, node_uuid):
        self.posts += 1
        raise RuntimeError("403")

    async def get_fetch_users_ips_result(self, job_id):
        raise RuntimeError("403")


async def test_sweep_all_forbidden_backs_off_and_reports(fake_panel):
    api = _Forbidden()
    fake_panel["api"] = api
    p = C.ConnectionsPoller()
    await p.tick(_live(100), _Logger())
    # неудачные попытки тоже в счёт лимита тика — не обходим весь парк
    assert api.posts == C.NODES_PER_TICK
    assert p.error == "connections_unavailable" and p.failures == 1
    assert p._next_allowed > __import__("time").time()
    await p.tick(_live(100), _Logger())            # общий backoff: запросов нет
    assert api.posts == C.NODES_PER_TICK


async def test_sweep_partial_failure_is_not_an_error_and_node_waits(fake_panel):
    class Flaky(_FakeConnApi):
        async def fetch_users_ips_by_node(self, node_uuid):
            if node_uuid == "n0":
                self.posts.append(node_uuid)
                raise RuntimeError("node gone")
            return await super().fetch_users_ips_by_node(node_uuid)

    api = Flaky()
    fake_panel["api"] = api
    p = C.ConnectionsPoller()
    await p._tick_impl(_live(2), _Logger())
    assert p.error is None and p.failures == 0      # одна нода не отвечает — не сбой панели
    assert p._st["n0"]["fails"] == 1 and p._st["n0"]["retry_at"] > __import__("time").time()
    await p._tick_impl(_live(2), _Logger())
    assert api.posts.count("n0") == 1               # у сбойной ноды своя пауза


async def test_sweep_job_without_id_is_a_failure(fake_panel):
    class NoJob(_FakeConnApi):
        async def fetch_users_ips_by_node(self, node_uuid):
            return {"response": {}}

    fake_panel["api"] = NoJob()
    p = C.ConnectionsPoller()
    await p._tick_impl(_live(1), _Logger())
    assert p._st["n0"]["fails"] == 1 and p.error == "connections_unavailable"


def test_snapshot_expires_after_max_age():
    import time
    p = C.ConnectionsPoller()
    p._st["n1"] = {"phase": "idle", "job": None, "ips": {"7": ["91.79.15.105"]},
                   "as_of": time.time() - 60, "fails": 0}
    assert p.user_ip("n1", 7) == "91.79.15.105" and p.age_s("n1") is not None
    # обновить не выходит уже дольше порога — прошлый адрес не выдаём за текущий
    p._st["n1"]["as_of"] = time.time() - C.SNAPSHOT_MAX_AGE_S - 1
    assert p.ips("n1") is None and p.user_ip("n1", 7) is None and p.age_s("n1") is None


async def test_snapshot_max_age_follows_fleet_size(fake_panel):
    import time
    fake_panel["api"] = _FakeConnApi()
    p = C.ConnectionsPoller()
    await p._tick_impl(_live(100), _Logger())
    # на 100 нодах штатный круг ~8 мин: снимок такого возраста — не сбой
    assert p.max_age_s() >= 2 * 8 * 60
    p._st["n5"] = {"phase": "idle", "job": None, "ips": {"7": ["91.79.15.105"]},
                   "as_of": time.time() - 9 * 60, "fails": 0}
    assert p.user_ip("n5", 7) == "91.79.15.105"


def test_shares_go_stale_when_polling_stops():
    step = M.quantum("1.00 GiB")
    snaps = [_snap(0.0, {"DIRECT": 0, "WARP": 0}, step),
             _snap(600.0, {"DIRECT": 80 * step, "WARP": 20 * step}, step)]
    assert _poller_with(snaps, age=M.INTERVAL_S).shares("n1") is not None
    # опрос падает или панель отдаёт пустой список: окно не обновляется,
    # и прошлые доли больше не рисуют линий
    assert _poller_with(snaps, age=M.STALE_S + 1).shares("n1") is None


async def test_metrics_failure_after_success_expires_shares(fake_panel, monkeypatch):
    import time
    step = M.quantum("1.00 GiB")
    p = _poller_with([_snap(0.0, {"DIRECT": 0, "WARP": 0}, step),
                      _snap(600.0, {"DIRECT": 80 * step, "WARP": 20 * step}, step)])
    assert p.shares("n1") is not None
    fake_panel["api"] = _FakeMetricsApi({"response": {"nodes": []}})
    now = time.time()
    monkeypatch.setattr(M.time, "time", lambda: now + M.STALE_S + 1)
    await p._tick_impl(_Logger())
    assert p.error == "metrics_empty" and p.shares("n1") is None


async def test_metrics_window_drops_snapshots_older_than_window(fake_panel):
    step = M.quantum("1.00 GiB")
    p = _poller_with([_snap(0.0, {"DIRECT": 0}, step)], age=M.WINDOW_S + 60)   # до долгого перерыва
    fake_panel["api"] = _FakeMetricsApi({"response": {"nodes": [{
        "nodeUuid": "n1", "outboundsStats": [{"tag": "DIRECT", "upload": "5.00 GiB", "download": "0"}]}]}})
    await p._tick_impl(_Logger())
    assert len(p._win["n1"]) == 1                    # старый снимок не тянет окно в прошлое


@pytest.mark.parametrize("payload", [
    {"response": {"configProfiles": None}},
    {"response": {"configProfiles": {"uuid": "p1"}}},
    {"response": "oops"},
    {"error": "x"},
    "garbage",
])
async def test_profiles_malformed_response_is_not_empty_success(fake_panel, payload):
    fake_panel["api"] = _FakePanel(payload)
    assert await D._profiles_by_uuid(_Logger()) is None


async def test_profiles_malformed_response_keeps_last_good(fake_panel, monkeypatch):
    monkeypatch.setattr(D, "PROFILES_TTL_S", 0.0)
    D._profiles_cache.update(ts=0.0, data=None, stale=False, last_log=0.0)
    fake_panel["api"] = _FakePanel({"response": {"configProfiles": [{"uuid": "p1", "name": "ok", "config": {}}]}})
    await D._profiles_cached(_Logger())
    fake_panel["api"] = _FakePanel({"response": {"configProfiles": None}})
    data, stale = await D._profiles_cached(_Logger())
    assert set(data) == {"p1"} and stale is True     # не пустой набор с DIRECT у всех


def test_by_outbound_mixed_fleet_keeps_rows_without_tags():
    rows = [
        {"user": "a", "node": "NEW", "node_uuid": "n1", "outbound": ["casc-fi"]},
        {"user": "b", "node": "NEW", "node_uuid": "n1", "outbound": ["DIRECT"]},
        {"user": "c", "node": "NEW", "node_uuid": "n1", "outbound": None, "ip_source": "panel"},
        {"user": "d", "node": "OLD", "node_uuid": "n2", "outbound": None},
    ]
    out = D._by_outbound(_payload(rows), ["casc-fi"])
    # b точно ходил мимо ветки — отфильтрован; у c и d аутбаунд не виден — остались
    assert [r["user"] for r in out["users"]] == ["a", "c", "d"]
    assert out["by_outbound"] is True and out["count"] == 3
    assert out["unverified_nodes"] == ["NEW", "OLD"]


def test_by_outbound_all_tagged_has_no_unverified():
    rows = [{"user": "a", "node": "NEW", "node_uuid": "n1", "outbound": ["casc-fi"]}]
    assert D._by_outbound(_payload(rows), ["casc-fi"])["unverified_nodes"] == []


def test_module_js_marks_rows_without_outbound():
    js = MODULE_JS
    assert "pd.unverified_nodes" in js and "tt.pUnverified" in js
    assert "pd.by_outbound && r.outbound == null" in js
    # подпись есть на обоих языках
    assert js.count("pUnverified:") == 2 and js.count("pUnverifiedNote:") == 2 and js.count("outUnknown:") == 2
