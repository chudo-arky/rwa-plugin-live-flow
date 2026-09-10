"""Сбор живого среза: ноды с онлайном и трафиком + форма графа из конфиг-профилей."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

# Человеческие названия для известных тегов. Незнакомые показываются как есть.
_SINK_TITLES = {
    "DIRECT": "Интернет",
    "BLOCK": "Блокировка",
}

# Протокол аутбаунда → род блока на схеме. От рода зависит, рисуем ли живые
# линии: измеримый поток есть только у выхода в интернет, для остальных веток
# числа лежат в access.log ноды, куда панель не смотрит.
_SINK_KIND = {
    "freedom": "internet",
    "blackhole": "block",
    "wireguard": "warp",
}

_KIND_ORDER = {"internet": 0, "warp": 1, "chain": 2, "block": 3}

# Протоколы, у которых аутбаунд ведёт на другой сервер (не терминальный выход).
# Если адрес назначения совпадает с адресом нашей же ноды — это каскад, и на
# схеме это ребро нода→нода, а не «выход».
_CHAIN_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard"}


def _outbound_addr(o: dict) -> str | None:
    """Адрес назначения аутбаунда — там, где xray его прячет по протоколам."""
    s = o.get("settings")
    if not isinstance(s, dict):
        return None
    for key in ("vnext", "servers"):
        arr = s.get(key)
        if isinstance(arr, list) and arr and isinstance(arr[0], dict):
            a = arr[0].get("address")
            if a:
                return str(a)
    peers = s.get("peers")  # wireguard: endpoint = host:port
    if isinstance(peers, list) and peers and isinstance(peers[0], dict):
        ep = peers[0].get("endpoint")
        if ep:
            return str(ep).rsplit(":", 1)[0]
    return None


RESOLVE_TTL_S = 600.0        # DNS-ответы для матчинга каскадов: адреса нод меняются редко
RESOLVE_FAIL_TTL_S = 60.0    # неудачу помним недолго, чтобы не залипнуть на сбое DNS
RESOLVE_TIMEOUT_S = 2.0
_resolve_cache: dict[str, tuple[float, frozenset[str]]] = {}


def _norm_host(h) -> str:
    return str(h or "").strip().lower().rstrip(".").strip("[]")


def _ip_literal(host: str) -> str | None:
    import ipaddress

    try:
        return str(ipaddress.ip_address(_norm_host(host)))
    except ValueError:
        return None


async def _resolve_hosts(hosts) -> dict[str, frozenset[str]]:
    """host → множество его IP. IP-литерал резолвится сам в себя, неудача —
    пустое множество (кэш короче). Никогда не бросает: каскад — украшение
    схемы, а не повод её уронить."""
    import asyncio
    import socket
    import time as _time

    now = _time.time()
    out: dict[str, frozenset[str]] = {}
    todo: list[str] = []
    for h in {_norm_host(x) for x in hosts if x}:
        if not h:
            continue
        lit = _ip_literal(h)
        if lit:
            out[h] = frozenset({lit})
            continue
        hit = _resolve_cache.get(h)
        if hit and now < hit[0]:
            out[h] = hit[1]
        else:
            todo.append(h)
    if todo:
        loop = asyncio.get_running_loop()

        async def one(h: str) -> None:
            try:
                infos = await asyncio.wait_for(loop.getaddrinfo(h, None, type=socket.SOCK_STREAM), RESOLVE_TIMEOUT_S)
                ips = frozenset(ip for ip in (_ip_literal(i[4][0]) for i in infos if i and i[4]) if ip)
            except Exception:  # noqa: BLE001
                ips = frozenset()
            _resolve_cache[h] = (now + (RESOLVE_TTL_S if ips else RESOLVE_FAIL_TTL_S), ips)
            out[h] = ips

        await asyncio.gather(*(one(h) for h in todo))
    return out


def _cascade_target(addr, own_uuid: str, addr_to_uuid: dict[str, str], resolved: dict[str, frozenset[str]]) -> str | None:
    """uuid нашей ноды, на которую ведёт аутбаунд, или None.

    Сначала строка к строке (домен = домен), затем IP: после переезда доменов
    адрес ноды в панели может быть IP, а аутбаунд — доменом (или наоборот), и
    строки уже не совпадают. Аутбаунд на саму себя каскадом не считается.
    """
    a = _norm_host(addr)
    if not a:
        return None
    hit = addr_to_uuid.get(a)
    if hit is None:
        for ip in resolved.get(a) or ():
            hit = addr_to_uuid.get(ip)
            if hit:
                break
    return hit if hit and hit != own_uuid else None


PROFILES_TTL_S = 60.0          # /data дёргает каждая вкладка раз в 5 с — профили столько не меняются
PROFILES_TIMEOUT_S = 15.0
PROFILES_LOG_EVERY_S = 300.0   # ошибку запроса логируем не чаще раза в 5 минут
_profiles_cache: dict = {"ts": 0.0, "data": None, "stale": False, "last_log": 0.0}


async def _profiles_cached(logger) -> tuple[dict[str, dict] | None, bool]:
    """Профили с кешем: (данные, stale). Свежие — не чаще раза в PROFILES_TTL_S;
    при ошибке отдаём последние удачные с пометкой stale, а None — только если
    удачных ещё не было."""
    import time as _time

    now = _time.time()
    c = _profiles_cache
    if c["data"] is not None and now - c["ts"] < PROFILES_TTL_S:
        return c["data"], c["stale"]
    quiet = now - c["last_log"] < PROFILES_LOG_EVERY_S
    fresh = await _profiles_by_uuid(logger, timeout=PROFILES_TIMEOUT_S, quiet=quiet)
    if fresh is not None:
        c.update(ts=now, data=fresh, stale=False)
        return fresh, False
    if not quiet:
        c["last_log"] = now
    c["ts"] = now          # не долбить панель каждые 5 с, пока она лежит
    c["stale"] = c["data"] is not None
    return c["data"], c["stale"]


async def _snippets_by_name(logger, timeout: float | None = None, quiet: bool = False) -> dict[str, list] | None:
    """Сниппеты панели: имя → содержимое (список аутбаундов или правил).

    В конфиг-профиле сниппет лежит нераскрытой ссылкой ``{"snippet": "имя"}``
    (панель подставляет его только при сборке конфига ноды), поэтому WARP,
    вынесенный в сниппет, без этого на схеме не появлялся.

    Возвращает ``None``, если запрос упал (сбой панели/таймаут) — это НЕ то же,
    что успешный пустой ответ ``{}``: при сбое профили со ссылками считаются
    незагруженными, и ``_profiles_cached`` оставляет последний удачный набор с
    пометкой stale. У клиента без метода сниппетов — ``{}``: раскрыть нечем,
    ссылки останутся неразрешёнными и будут помечены в ответе."""
    import asyncio

    from web.backend.core.plugin_api import panel_api

    api = panel_api()
    if not hasattr(api, "get_snippets"):
        return {}
    try:
        coro = api.get_snippets()
        resp = await (asyncio.wait_for(coro, timeout=timeout) if timeout else coro)
    except Exception:  # noqa: BLE001
        if not quiet:
            logger.exception("live_flow: snippets request failed")
        return None
    body = resp.get("response") if isinstance(resp, dict) else None
    items = body.get("snippets") if isinstance(body, dict) else None
    if not isinstance(body, dict) or not isinstance(items, list):
        if not quiet:
            logger.warning("live_flow: snippets response has unexpected shape")
        return None
    out: dict[str, list] = {}
    for s in items if isinstance(items, list) else []:
        if not isinstance(s, dict) or not s.get("name"):
            continue
        content = s.get("snippet")
        if isinstance(content, dict):
            content = [content]
        if isinstance(content, list):
            out[str(s["name"])] = [c for c in content if isinstance(c, dict)]
    return out


def _snippet_refs(items: list) -> list[str]:
    """Имена сниппетов, на которые ссылается список аутбаундов."""
    return [str(o.get("snippet")) for o in items if isinstance(o, dict) and "snippet" in o and not o.get("tag")]


def _expand_snippets(items: list, snippets: dict[str, list]) -> tuple[list, list[str]]:
    """Заменяет ссылки ``{"snippet": "имя"}`` содержимым сниппета (один уровень:
    сниппет внутри сниппета панель не поддерживает). Возвращает (список,
    неразрешённые имена): неизвестное имя не пропадает молча — оно попадает в
    ответ, а вместо него НЕ подставляется DIRECT."""
    out: list = []
    unresolved: list[str] = []
    for o in items:
        if isinstance(o, dict) and "snippet" in o and not o.get("tag"):
            name = str(o.get("snippet"))
            if name in snippets:
                out.extend(snippets[name])
            elif name not in unresolved:
                unresolved.append(name)
        else:
            out.append(o)
    return out, unresolved


_NO_COMPUTED = object()   # у клиента админки нет метода computed-config (старая версия)


async def _computed_outbounds(logger, uuids: list[str], timeout: float | None = None, quiet: bool = False):
    """Аутбаунды профилей с раскрытыми сниппетами: uuid → список.

    ``GET /api/config-profiles/{uuid}/computed-config`` — панель сама
    подставляет сниппеты везде (аутбаунды, правила, балансеры, вложенные) и
    ровно так, как отдаёт конфиг ноде. Один запрос на профиль со ссылками.
    ``_NO_COMPUTED`` — метода у клиента нет; ``None`` — какой-то из запросов
    упал или ответ не той формы (набор профилей считается незагруженным)."""
    import asyncio

    from web.backend.core.plugin_api import panel_api

    api = panel_api()
    if not hasattr(api, "get_config_profile_computed"):
        return _NO_COMPUTED

    async def one(uuid: str) -> list:
        coro = api.get_config_profile_computed(uuid)
        resp = await (asyncio.wait_for(coro, timeout=timeout) if timeout else coro)
        body = resp.get("response") if isinstance(resp, dict) else None
        cfg = body.get("config") if isinstance(body, dict) else None
        if isinstance(cfg, str):
            cfg = json.loads(cfg)
        if not isinstance(cfg, dict):
            raise ValueError("computed-config: unexpected shape")
        outs = cfg.get("outbounds")
        return outs if isinstance(outs, list) else []

    try:
        results = await asyncio.gather(*(one(u) for u in uuids))
    except Exception:  # noqa: BLE001
        if not quiet:
            logger.exception("live_flow: computed-config request failed")
        return None
    return dict(zip(uuids, results, strict=True))


async def _profiles_by_uuid(logger, timeout: float | None = None, quiet: bool = False) -> dict[str, dict] | None:
    """Конфиг-профили панели: uuid → имя, инбаунды, аутбаунды. None — запрос упал."""
    import asyncio

    from web.backend.core.plugin_api import panel_api

    try:
        coro = panel_api().get_config_profiles()
        resp = await (asyncio.wait_for(coro, timeout=timeout) if timeout else coro)
    except Exception:  # noqa: BLE001 — схему не роняем, но и выходы не выдумываем
        if not quiet:
            logger.exception("live_flow: config profiles request failed")
        return None

    body = resp.get("response") if isinstance(resp, dict) else None
    items = body.get("configProfiles") if isinstance(body, dict) else None
    if not isinstance(items, list):
        items = []
    parsed: list[tuple[dict, dict]] = []
    for p in items:
        # Один кривой профиль не должен ронять схему: всё, что не той формы, пропускаем.
        if not isinstance(p, dict) or not p.get("uuid"):
            continue
        cfg = p.get("config")
        if isinstance(cfg, str):
            try:
                cfg = json.loads(cfg)
            except ValueError:
                cfg = {}
        parsed.append((p, cfg if isinstance(cfg, dict) else {}))
    # Профили со ссылками на сниппеты берём у панели уже раскрытыми
    # (computed-config, один запрос на такой профиль; обычные профили — без
    # лишнего запроса). У старой админки без этого метода — запасной путь:
    # сниппеты по именам. Сбой любого запроса — набор профилей не загружен
    # целиком (None): иначе ссылки исчезли бы, а пустой список выходов лёг бы
    # в кэш как «удачный».
    raw_outs = {
        str(p["uuid"]): (cfg.get("outbounds") if isinstance(cfg.get("outbounds"), list) else [])
        for p, cfg in parsed
    }
    ref_uuids = [u for u, o in raw_outs.items() if _snippet_refs(o)]
    computed: dict[str, list] = {}
    snippets: dict[str, list] = {}
    if ref_uuids:
        got = await _computed_outbounds(logger, ref_uuids, timeout=timeout, quiet=quiet)
        if got is None:
            return None
        if got is _NO_COMPUTED:
            sn = await _snippets_by_name(logger, timeout=timeout, quiet=quiet)
            if sn is None:
                return None
            snippets = sn
        else:
            computed = got
    out: dict[str, dict] = {}
    for p, cfg in parsed:
        uuid = str(p["uuid"])
        raw = raw_outs[uuid]
        # в раскрытом конфиге ссылок остаться не должно; если остались — они неразрешённые
        outs, unresolved = _expand_snippets(computed[uuid], {}) if uuid in computed else _expand_snippets(raw, snippets)
        ins = cfg.get("inbounds") if isinstance(cfg.get("inbounds"), list) else []
        out[str(p.get("uuid"))] = {
            "name": p.get("name"),
            # были ли выходы в сыром конфиге (включая ссылки): пустой список при
            # неразрешённой ссылке — не повод подставлять DIRECT (см. _effective_outbounds)
            "has_outbounds": bool(raw),
            "snippets_unresolved": unresolved,
            "outbounds": [
                {"tag": str(o.get("tag")), "protocol": str(o.get("protocol") or ""), "addr": _outbound_addr(o)}
                for o in outs
                if isinstance(o, dict) and o.get("tag")
            ],
            "inbounds": [str(i.get("tag")) for i in ins if isinstance(i, dict) and i.get("tag")],
            "cdn_inbounds": [str(i.get("tag")) for i in ins if isinstance(i, dict) and i.get("tag") and _inbound_behind_cdn(i)],
        }
    return out


# HTTP-транспорты, которые можно проксировать через CDN. Reality сквозь CDN не
# ходит, значит такой инбаунд принимает клиента напрямую.
_CDN_NETWORKS = frozenset({"ws", "websocket", "xhttp", "splithttp", "httpupgrade", "grpc", "h2", "http"})


def _inbound_behind_cdn(ib: dict) -> bool:
    """Инбаунд за CDN/обратным прокси. Одного HTTP-транспорта мало (xhttp/ws с TLS
    могут торчать в интернет напрямую — ложное срабатывание у тех, кто CDN не
    настраивал), поэтому нужен явный признак прокси перед Xray: либо security none
    (голый HTTP-транспорт наружу не выставляют — TLS терминирует прокси), либо
    sockopt.trustedXForwardedFor (его ставят только осознанно под CDN)."""
    ss = ib.get("streamSettings") if isinstance(ib.get("streamSettings"), dict) else {}
    net = str(ss.get("network") or "tcp").lower()
    sec = str(ss.get("security") or "none").lower()
    so = ss.get("sockopt") if isinstance(ss.get("sockopt"), dict) else {}
    return net in _CDN_NETWORKS and sec != "reality" and (sec == "none" or bool(so.get("trustedXForwardedFor")))


def _cdn_tags(profiles: dict | None) -> set[str]:
    return {t for p in (profiles or {}).values() for t in (p.get("cdn_inbounds") or [])}


_DEFAULT_OUTBOUNDS = [{"tag": "DIRECT", "protocol": "freedom"}]


def _effective_outbounds(profile: dict, profiles_available: bool) -> list[dict]:
    """Выходы ноды по её профилю.

    DIRECT по умолчанию — только когда профили получены, но у ноды профиля нет
    или в его конфиге не было выходов вовсе. Профиль, у которого выходы были,
    но после раскрытия сниппетов список опустел (ссылка не разрешилась),
    остаётся ПУСТЫМ: выдуманный DIRECT скрыл бы проблему. При упавшем запросе
    профилей выходы не рисуем вовсе.
    """
    if not profiles_available:
        return []
    if not profile:
        return list(_DEFAULT_OUTBOUNDS)
    if profile.get("has_outbounds"):
        return list(profile.get("outbounds") or [])
    return list(profile.get("outbounds") or _DEFAULT_OUTBOUNDS)


def _profile_uuid(raw: Any) -> str | None:
    """UUID активного профиля из raw_data ноды (панель кладёт его как JSON)."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:  # noqa: BLE001
            return None
    if not isinstance(raw, dict):
        return None
    profile = raw.get("configProfile")
    if not isinstance(profile, dict):
        return None
    value = profile.get("activeConfigProfileUuid")
    return str(value) if value else None


# Окно «активен» (секунды от текущего времени). Живой опрос панели (poller)
# отсчитывает его от now(); DB-фолбэк — тоже от now(), но с запасом на лаг
# синка админки (юзеры синкаются раз в SYNC_LAG_S): в фолбэке «активен» =
# «был активен не позже окно+лаг назад», и UI помечает этот режим как «синк БД».
ONLINE_WINDOW_S = 180.0
SYNC_LAG_S = 300.0

# onlineAt из raw_data — только если похож на ISO-дату; мусор → NULL, а не ошибка каста.
_ONLINE_AT_SQL = ("CASE WHEN raw_data::jsonb->'userTraffic'->>'onlineAt' ~ "
                  "'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?(Z|[+-][0-9]{2}:?[0-9]{2})?$' "
                  "THEN (raw_data::jsonb->'userTraffic'->>'onlineAt')::timestamptz END")
_AS_OF_SQL = "(SELECT max(" + _ONLINE_AT_SQL + ") FROM users)"  # nosec B608 — константы, без пользовательского ввода


async def _active_by_node(ctx) -> dict[str, int] | None:
    """Сколько людей реально активны на каждой ноде — по панели.

    ``users_online`` ноды считает и клиентов, которые пингуют все ноды
    авто-выбором (22.08.2026: сумма по нодам 62 при 20 реальных). Реальных
    считаем по ``users.raw_data.userTraffic``: ``lastConnectedNodeUuid`` +
    ``onlineAt`` не старше окна. None — запрос упал (UI тогда число не рисует).
    """
    try:
        rows = await ctx.db.fetch(  # nosec B608 — SQL из констант модуля, данные только через $1
            """
            SELECT raw_data::jsonb->'userTraffic'->>'lastConnectedNodeUuid' AS nu, count(*) AS c,
                   """ + _AS_OF_SQL + """ AS as_of
            FROM users
            WHERE """ + _ONLINE_AT_SQL + """ > now() - make_interval(secs => $1)
            GROUP BY 1
            """,
            ONLINE_WINDOW_S + SYNC_LAG_S,
        )
    except Exception:  # noqa: BLE001
        ctx.logger.exception("live_flow: active-by-node query failed")
        return None
    as_of = rows[0]["as_of"] if rows else None
    return {"by_node": {str(r["nu"]): int(r["c"]) for r in rows if r["nu"]}, "as_of": as_of}


async def collect(ctx) -> dict:
    """Срез на «сейчас»: числа онлайна берём у панели, они авторитетнее наших.

    Скорость VPN и живые onlineAt — из ``poller`` (опрос API панели каждые
    15 с); пока опрос не успел или упал — активные по синку БД (лаг до 5 мин),
    скорость VPN не показывается (UI падает на сетевую ↑/↓ агента).
    """
    from .poller import POLLER

    live = POLLER.fresh
    split: dict[str, dict] = {}
    total_split = {"mobile": 0.0, "fixed": 0.0, "cdn": 0.0, "unknown": 0.0, "mobile_users": 0, "fixed_users": 0, "cdn_users": 0, "unknown_users": 0}
    if live:
        active = POLLER.active_by_node()
        active_as_of = POLLER.online_ref_iso()
        split, total_split = await _vpn_split(ctx, POLLER)
    else:
        act = await _active_by_node(ctx)
        active = act["by_node"] if act else None
        active_as_of = act["as_of"].isoformat() if act and act["as_of"] else None
    rows = await ctx.db.fetch(
        """
        SELECT uuid::text AS uuid,
               name,
               address,
               COALESCE(users_online, 0) AS users_online,
               COALESCE(net_tx_bps, 0)   AS tx,
               COALESCE(net_rx_bps, 0)   AS rx,
               is_connected,
               raw_data,
               CASE WHEN raw_data::jsonb->>'viewPosition' ~ '^-?[0-9]+$'
                    THEN (raw_data::jsonb->>'viewPosition')::int END AS position
        FROM nodes
        WHERE is_disabled = false
        -- порядок как в панели Remnawave (viewPosition — перетаскивание в её UI);
        -- у кого позиции нет — в конец по имени
        ORDER BY position NULLS LAST, name
        """
    )

    profiles, profiles_stale = await _profiles_cached(ctx.logger)
    profiles_available = profiles is not None

    # адрес ноды → uuid: по нему ловим каскад (аутбаунд на нашу же ноду).
    # Карта держит и строку адреса, и его IP после резолва — аутбаунды тоже
    # резолвим, чтобы «домен ↔ IP» совпадали (см. _cascade_target).
    chain_addrs = [
        o.get("addr") for p in (profiles or {}).values() for o in (p.get("outbounds") or [])
        if o.get("addr") and o.get("protocol") in _CHAIN_PROTOCOLS
    ]
    resolved = await _resolve_hosts([r["address"] for r in rows if r["address"]] + chain_addrs)
    addr_to_uuid: dict[str, str] = {}
    for r in rows:
        a = _norm_host(r["address"])
        if not a:
            continue
        addr_to_uuid.setdefault(a, r["uuid"])
        for ip in resolved.get(a) or ():
            addr_to_uuid.setdefault(ip, r["uuid"])

    sinks: dict[str, dict] = {}
    nodes: list[dict] = []

    snippets_unresolved: list[str] = []
    for row in rows:
        profile = (profiles or {}).get(_profile_uuid(row["raw_data"]) or "") or {}
        outbounds = _effective_outbounds(profile, profiles_available)
        for name in profile.get("snippets_unresolved") or []:
            if name not in snippets_unresolved:
                snippets_unresolved.append(name)

        node_sinks: list[str] = []
        cascades: list[str] = []
        for outbound in outbounds:
            tag = outbound["tag"]
            proto = outbound["protocol"]
            # Каскад: аутбаунд-цепочка, ведущая на другую НАШУ ноду. Это не выход,
            # а прыжок — рисуем ребром нода→нода, в список выходов не кладём.
            target = _cascade_target(outbound.get("addr"), row["uuid"], addr_to_uuid, resolved) if proto in _CHAIN_PROTOCOLS else None
            if target:
                if target not in cascades:
                    cascades.append(target)
                continue
            kind = _SINK_KIND.get(proto, "chain")
            sink = {"tag": tag, "title": _SINK_TITLES.get(tag, tag), "kind": kind}
            if kind == "chain" and outbound.get("addr"):
                sink["addr"] = _norm_host(outbound.get("addr"))   # цепочка на чужой сервер — куда именно
            sinks.setdefault(tag, sink)
            node_sinks.append(tag)

        nodes.append(
            {
                "uuid": row["uuid"],
                "name": row["name"],
                "position": row["position"],
                # счётчик ноды: живой из опроса панели, иначе из синка БД
                "users": int((POLLER.nodes.get(row["uuid"]) or {}).get("users_online", row["users_online"] or 0)) if live else int(row["users_online"] or 0),
                # Сетевая скорость хоста (агент rw-admin, net_*_bps — БАЙТЫ/с,
                # несмотря на имя) — справочно, в тултипе: там и SSH, и мониторинг.
                "tx_mbps": round(float(row["tx"] or 0) * 8 / 1e6, 2),
                "rx_mbps": round(float(row["rx"] or 0) * 8 / 1e6, 2),
                # VPN-скорость: дельта trafficUsedBytes ноды (xray) из панели;
                # None — опрос ещё не набрал двух разных значений или неживой.
                "vpn_mbps": (None if (not live or POLLER.node_bps(row["uuid"]) is None) else round(POLLER.node_bps(row["uuid"]) * 8 / 1e6, 2)),
                # деление VPN-трафика по типу сети юзера (сумма по-юзерных
                # скоростей панели; класс — ip_metadata по текущему IP)
                "vpn_split": split.get(row["uuid"]),
                "connected": bool(row["is_connected"]),
                # реально активных по панели (без пингов авто-выбора); None — нет данных
                "active": (active.get(row["uuid"], 0) if active is not None else None),
                "profile": profile.get("name"),
                "inbounds": profile.get("inbounds") or [],
                "sinks": node_sinks,
                "cascades": cascades,
            }
        )

    ordered = sorted(sinks.values(), key=lambda s: (_KIND_ORDER.get(s["kind"], 9), s["tag"]))
    return {
        "total_users": sum(n["users"] for n in nodes),
        "total_active": (sum(active.values()) if active is not None else None),
        "active_window_s": int(ONLINE_WINDOW_S if live else ONLINE_WINDOW_S + SYNC_LAG_S),
        # свежайший onlineAt — справочно («срез панели» в шапке)
        "active_as_of": active_as_of,
        # откуда живые данные: "panel-live" (опрос API) или "db-sync" (лаг до 5 мин)
        "live_source": "panel-live" if live else "db-sync",
        "vpn_split_total": (total_split if live else None),
        "poll_age_s": (round(POLLER.age_s(), 1) if POLLER.age_s() is not None else None),
        "poll_error": POLLER.error,          # только код: panel_unavailable | panel_timeout | None
        "poll_truncated": bool(POLLER.truncated),
        "nodes": nodes,
        "sinks": ordered,
        "profiles_available": profiles_available,
        "profiles_stale": bool(profiles_stale),
        # сниппеты, на которые ссылаются профили нод, но которых у панели нет:
        # ветки из них на схеме отсутствуют, UI показывает предупреждение
        "snippets_unresolved": snippets_unresolved,
    }


async def node_users(ctx, node_uuid: str) -> dict | None:
    """Кто сейчас на ноде, с IP и AS. None — ноды нет.

    🔴 Источник «кто на ноде» — ПАНЕЛЬ, а не ``user_connections``:
    ``users.raw_data.userTraffic.lastConnectedNodeUuid`` + ``onlineAt`` (панель
    пишет их из xray-статистики нод, админка синкает раз в 5 минут — окно
    отсчитывается от среза, см. ``_AS_OF_SQL``). В
    ``user_connections`` одна открытая строка на (юзер, IP), и каждый батч
    любой ноды переписывает ``node_uuid`` на себя — с клиентами, которые
    пингуют все ноды авто-выбором, «нода» там = последний отчитавшийся агент
    (проверено 22.08.2026: счётчик по ноде скачет 0→9→0 за секунды).
    Из ``user_connections`` берём только IP юзера (открытые строки или за
    последние 10 мин, любая нода) и к ним ``ip_metadata`` (ASN/гео).

    Счётчик ноды ``users_online`` (панель считает по xray, с пингами
    авто-выбора) отдаём рядом — UI показывает «по панели активны N · счётчик
    ноды M». Одна строка на пару (пользователь, IP).
    """
    from .poller import POLLER

    node = await ctx.db.fetchrow(
        "SELECT uuid::text AS uuid, name, COALESCE(users_online, 0) AS users_online "
        "FROM nodes WHERE uuid::text = $1",
        node_uuid,
    )
    if not node:
        return None
    if POLLER.fresh:
        return await _node_users_live(ctx, node, node_uuid, POLLER)
    try:
        return await _node_users_db(ctx, node, node_uuid)
    except Exception:  # noqa: BLE001 — фолбэк по БД: кривая дата в raw_data и т.п. не должны давать 500
        ctx.logger.exception("live_flow: node users db-fallback failed")
        return {
            "node": {"uuid": node["uuid"], "name": node["name"], "users_online": int(node["users_online"] or 0)},
            "users": [], "count": 0, "window_s": int(ONLINE_WINDOW_S + SYNC_LAG_S),
            "as_of": None, "source": "db-sync", "unavailable": True,
        }


async def _node_users_db(ctx, node, node_uuid: str) -> dict:
    rows = await ctx.db.fetch(  # nosec B608 — SQL из констант модуля, данные только через $1/$2
        """
        WITH online AS (
            SELECT u.uuid AS user_uuid, u.username, u.email, u.telegram_id, u.tag,
                   """ + _ONLINE_AT_SQL.replace("raw_data", "u.raw_data") + """ AS online_at
            FROM users u
            WHERE u.raw_data::jsonb->'userTraffic'->>'lastConnectedNodeUuid' = $1
              AND """ + _ONLINE_AT_SQL + """ > now() - make_interval(secs => $2)
        ),
        ips AS (
            SELECT DISTINCT ON (c.user_uuid, c.ip_address)
                   c.user_uuid, c.ip_address, c.connected_at,
                   c.device_info->>'inbound_tag' AS inbound
            FROM user_connections c
            JOIN online o ON o.user_uuid = c.user_uuid
            WHERE c.disconnected_at IS NULL OR c.connected_at > now() - interval '10 minutes'
            ORDER BY c.user_uuid, c.ip_address, c.connected_at DESC
        )
        SELECT o.username, o.email, o.telegram_id, o.tag, o.online_at,
               i.ip_address::text AS ip_address, i.connected_at, i.inbound,
               m.asn, m.asn_org, m.country_code, m.city,
               m.is_mobile, m.is_hosting, m.is_vpn, m.is_proxy
        FROM online o
        LEFT JOIN ips i ON i.user_uuid = o.user_uuid
        LEFT JOIN ip_metadata m ON m.ip_address = i.ip_address
        ORDER BY o.online_at DESC, o.username, i.connected_at DESC
        """,
        node_uuid,
        ONLINE_WINDOW_S + SYNC_LAG_S,
    )
    users = []
    seen_users = set()
    for r in rows:
        key = r["username"] or r["email"] or str(r["telegram_id"])
        seen_users.add(key)
        users.append(
            {
                "user": r["username"] or r["email"] or (str(r["telegram_id"]) if r["telegram_id"] else "?"),
                "telegram_id": r["telegram_id"],
                "tag": r["tag"],
                "ip": r["ip_address"],
                "asn": r["asn"],
                "as_name": r["asn_org"],
                "country": r["country_code"],
                "city": r["city"],
                "mobile": bool(r["is_mobile"]) if r["is_mobile"] is not None else None,
                "hosting": bool(r["is_hosting"] or r["is_vpn"] or r["is_proxy"]),
                "inbound": r["inbound"],
                "cdn": r["inbound"] in _cdn_tags(_profiles_cache.get("data")),  # маршрут через CDN/прокси — метка в строке
                # «активен»: onlineAt панели; «since» оставлено для UI-совместимости
                "since": r["online_at"].isoformat() if r["online_at"] else None,
                "ip_since": r["connected_at"].isoformat() if r["connected_at"] else None,
            }
        )
    return {
        "node": {"uuid": node["uuid"], "name": node["name"], "users_online": int(node["users_online"] or 0)},
        "users": users,
        "count": len(seen_users),
        "window_s": int(ONLINE_WINDOW_S + SYNC_LAG_S),
        "as_of": (rows[0]["online_at"].isoformat() if rows and rows[0]["online_at"] else None),
        "source": "db-sync",
    }


# connection_type, за которым не видно реального клиента: нода за CDN/прокси
# видит IP Cloudflare и т. п. — это не «Wi-Fi/LAN», а «неизвестно» с причиной cdn.
_HOSTING_TYPES = frozenset({"datacenter", "hosting", "vpn", "proxy", "cdn", "tor"})


def _net_class(is_mobile, connection_type, hosting: bool = False) -> str:
    """mobile | fixed | unknown по ip_metadata (is_mobile / connection_type / is_hosting)."""
    ct = (connection_type or "").lower()
    if hosting or ct in _HOSTING_TYPES:
        return "unknown"
    if is_mobile is True or ct == "mobile":
        return "mobile"
    if is_mobile is False or connection_type:
        return "fixed"
    return "unknown"


def _is_local_ip(ip) -> bool:
    """127.0.0.1 / 10.x / fd00:: — Xray за локальным прокси, клиента не видит."""
    import ipaddress
    try:
        a = ipaddress.ip_address(str(ip).split("/")[0])
    except ValueError:
        return False
    return a.is_loopback or a.is_private or a.is_link_local


def _unknown_why(has_conn: bool, has_meta: bool, via_cdn: bool = False) -> str:
    """Причина «неизвестно»: cdn (подключение пришло через инбаунд за CDN/прокси или
    с хостингового/локального IP — нода не видит клиента, см. README) | no_conn
    (агент ноды не сообщил IP) | no_meta (IP ещё не обогащён GeoIP)."""
    if via_cdn:
        return "cdn"
    return "no_conn" if not has_conn else "no_meta" if not has_meta else "cdn"


UNKNOWN_WHY = ("no_conn", "no_meta", "cdn")
_cls_why: dict[str, str] = {}  # id панели → причина, только для класса unknown


CLASSIFY_TTL_S = 45.0
_cls_cache: dict = {"ts": 0.0, "map": {}}


async def _classify_users(ctx, ids_str: list) -> dict[str, str]:
    """id панели (строкой) → mobile | fixed | unknown по текущему IP юзера.

    Кэш на CLASSIFY_TTL_S: /data дёргается каждой вкладкой раз в 5 с, а класс
    сети меняется редко. Новые id, которых в кэше нет, дорезолвим сразу.
    """
    import time as _time

    wanted = [str(u) for u in ids_str if str(u).isdigit()]
    now = _time.time()
    cached = _cls_cache["map"] if now - _cls_cache["ts"] < CLASSIFY_TTL_S else {}
    missing = [u for u in wanted if u not in cached]
    if not missing:
        return {u: cached[u] for u in wanted}
    fresh = await _classify_users_db(ctx, missing)
    merged = dict(cached)
    merged.update(fresh)
    if not cached:
        _cls_cache["ts"] = now
    _cls_cache["map"] = merged
    return {u: merged.get(u, "unknown") for u in wanted}


async def _classify_users_db(ctx, ids_str: list) -> dict[str, str]:
    ids = [int(u) for u in ids_str if str(u).isdigit()]
    cls: dict[str, str] = {}
    if not ids:
        return cls
    try:
        rows = await ctx.db.fetch(
            """
            SELECT u.id, m.is_mobile, m.connection_type,
                   (m.is_hosting OR m.is_vpn OR m.is_proxy OR m.is_tor) AS hosting,
                   c.ip_address IS NOT NULL AS has_conn, m.ip_address IS NOT NULL AS has_meta,
                   c.ip_address::text AS ip, c.device_info->>'inbound_tag' AS inbound
            FROM users u
            LEFT JOIN LATERAL (
                SELECT c.ip_address, c.device_info FROM user_connections c
                WHERE c.user_uuid = u.uuid
                  AND (c.disconnected_at IS NULL OR c.connected_at > now() - interval '10 minutes')
                ORDER BY c.connected_at DESC LIMIT 1
            ) c ON true
            LEFT JOIN ip_metadata m ON m.ip_address = c.ip_address
            WHERE u.id = ANY($1::bigint[])
            """,
            ids,
        )
        cdn_tags = _cdn_tags(_profiles_cache.get("data"))
        for r in rows:
            # 127.0.0.1 — Xray за локальным прокси без проброса заголовков: клиента не видно.
            # Если прокси пробрасывает X-Forwarded-For, IP настоящий и GeoIP решает как обычно;
            # тег CDN-инбаунда тогда лишь подсказывает причину, когда класс всё равно unknown.
            local = _is_local_ip(r["ip"])
            # По слову владельца: трафик, пришедший через инбаунд за CDN, — отдельная группа «CDN»
            # (маршрут приёма важнее типа сети клиента). 127.0.0.1 без тега — «неизвестно».
            if r["inbound"] in cdn_tags:
                k = cls[str(r["id"])] = "cdn"
            else:
                k = cls[str(r["id"])] = "unknown" if local else _net_class(r["is_mobile"], r["connection_type"], bool(r["hosting"]))
            if k == "unknown":
                _cls_why[str(r["id"])] = _unknown_why(bool(r["has_conn"]), bool(r["has_meta"]), local)
            else:
                _cls_why.pop(str(r["id"]), None)
        for u in ids_str:
            cls.setdefault(str(u), "unknown")
            _cls_why.setdefault(str(u), "no_conn")
    except Exception:  # noqa: BLE001 — деление не важнее схемы
        ctx.logger.exception("live_flow: classify users query failed")
    return cls


async def _vpn_split(ctx, poller) -> tuple[dict[str, dict], dict]:
    """Деление VPN-трафика по типу сети: мобильный / Wi-Fi-LAN / неизвестно.

    По каждому активному юзеру (poller) — его скорость (дельта usedTrafficBytes)
    и класс сети по текущему IP (последняя строка user_connections → ip_metadata:
    ``is_mobile`` / ``connection_type``). Суммы по ноде (lastConnectedNodeUuid)
    и общие. Скорости в Мбит/с, плюс число юзеров в каждом классе.
    """
    act = poller.active_users()
    if not act:
        return {}, {"mobile": 0.0, "fixed": 0.0, "cdn": 0.0, "unknown": 0.0, "mobile_users": 0, "fixed_users": 0, "cdn_users": 0, "unknown_users": 0}
    cls = await _classify_users(ctx, [uid for uid, _ in act])
    def blank():
        return {"mobile": 0.0, "fixed": 0.0, "cdn": 0.0, "unknown": 0.0, "mobile_users": 0, "fixed_users": 0, "cdn_users": 0, "unknown_users": 0}
    per_node: dict[str, dict] = {}
    total = blank()
    why = dict.fromkeys(UNKNOWN_WHY, 0)
    for uid, u in act:
        nu = u.get("node_uuid")
        k = cls.get(str(uid), "unknown")
        bps = poller.user_bps(str(uid)) or 0.0
        mbps = bps * 8 / 1e6
        total[k] += mbps
        total[k + "_users"] += 1
        if k == "unknown":
            why[_cls_why.get(str(uid), "no_conn")] += 1
        if nu:
            d = per_node.setdefault(nu, blank())
            d[k] += mbps
            d[k + "_users"] += 1
    for d in list(per_node.values()) + [total]:
        for k in ("mobile", "fixed", "cdn", "unknown"):
            d[k] = round(d[k], 2)
    if total["unknown_users"]:
        total["unknown_why"] = why  # почему «неизвестно» — подсказка в карточке группы
    return per_node, total


async def _users_rows(ctx, poller, live_users: list, with_node: bool = False) -> list[dict]:
    """Строки для панели: (id, user) из poller → юзер + IP/AS из БД (+ имя ноды)."""
    live_users = sorted(live_users, key=lambda x: (x[1].get("online_at") or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
    # ключ poller — числовой id панели; user_connections ходит по users.uuid админки
    ids = [int(uid) for uid, _ in live_users if str(uid).isdigit()]
    id2uuid: dict[str, str] = {}
    if ids:
        for r in await ctx.db.fetch("SELECT id, uuid::text AS uuid FROM users WHERE id = ANY($1::bigint[])", ids):
            id2uuid[str(r["id"])] = r["uuid"]
    uuids = [id2uuid[uid] for uid, _ in live_users if uid in id2uuid]
    ip_rows = []
    if uuids:
        ip_rows = await ctx.db.fetch(
            """
            SELECT DISTINCT ON (c.user_uuid, c.ip_address)
                   c.user_uuid::text AS user_uuid, c.ip_address::text AS ip_address, c.connected_at,
                   c.device_info->>'inbound_tag' AS inbound,
                   m.asn, m.asn_org, m.country_code, m.city,
                   m.is_mobile, m.is_hosting, m.is_vpn, m.is_proxy
            FROM user_connections c
            LEFT JOIN ip_metadata m ON m.ip_address = c.ip_address
            WHERE c.user_uuid = ANY($1::uuid[])
              AND (c.disconnected_at IS NULL OR c.connected_at > now() - interval '10 minutes')
            ORDER BY c.user_uuid, c.ip_address, c.connected_at DESC
            """,
            uuids,
        )
    by_user: dict[str, list] = {}
    for r in ip_rows:
        by_user.setdefault(r["user_uuid"], []).append(r)
    users = []
    for uid, u in live_users:
        who = u.get("username") or u.get("email") or (str(u.get("telegram_id")) if u.get("telegram_id") else "?")
        base = {
            "user": who,
            "telegram_id": u.get("telegram_id"),
            "tag": u.get("tag"),
            "since": u["online_at"].isoformat() if u.get("online_at") else None,
            "vpn_mbps": (round(poller.user_bps(uid) * 8 / 1e6, 2) if poller.user_bps(uid) is not None else None),
        }
        if with_node:
            base["node"] = (poller.nodes.get(u.get("node_uuid") or "") or {}).get("name")
            base["node_uuid"] = u.get("node_uuid")
        rows_u = sorted(by_user.get(id2uuid.get(uid, ""), []), key=lambda r: r["connected_at"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        if not rows_u:
            users.append(dict(base, ip=None, asn=None, as_name=None, country=None, city=None, mobile=None, hosting=False, inbound=None, ip_since=None))
            continue
        for r in rows_u:
            users.append(dict(
                base,
                ip=r["ip_address"], asn=r["asn"], as_name=r["asn_org"], country=r["country_code"], city=r["city"],
                mobile=(bool(r["is_mobile"]) if r["is_mobile"] is not None else None),
                hosting=bool(r["is_hosting"] or r["is_vpn"] or r["is_proxy"]),
                inbound=r["inbound"], cdn=r["inbound"] in _cdn_tags(_profiles_cache.get("data")),
                ip_since=r["connected_at"].isoformat() if r["connected_at"] else None,
            ))
    return users


async def _node_users_live(ctx, node, node_uuid: str, poller) -> dict:
    """То же, что node_users, но онлайн — из живого опроса панели (без лага синка)."""
    live_users = [(uid, u) for uid, u in poller.active_users() if u.get("node_uuid") == node_uuid]
    users = await _users_rows(ctx, poller, live_users)
    live_node = poller.nodes.get(node_uuid) or {}
    return {
        "node": {"uuid": node["uuid"], "name": node["name"], "users_online": int(live_node.get("users_online", node["users_online"] or 0))},
        "users": users,
        "count": len(live_users),
        "window_s": int(ONLINE_WINDOW_S),
        "as_of": poller.online_ref_iso(),
        "source": "panel-live",
    }


async def _nodes_users(ctx, node_uuids: set[str], payload: dict) -> dict:
    """Сводный список активных на наборе нод (панель live); без опроса — пустой."""
    from .poller import POLLER

    if not POLLER.fresh:
        payload.update(users=[], count=0, window_s=int(ONLINE_WINDOW_S), as_of=None, source="db-sync", unavailable=True)
        return payload
    chosen = [(uid, u) for uid, u in POLLER.active_users() if u.get("node_uuid") in node_uuids]
    users = await _users_rows(ctx, POLLER, chosen, with_node=True)
    mbps = sum((POLLER.user_bps(uid) or 0.0) * 8 / 1e6 for uid, _ in chosen)
    payload.update(
        users=users, count=len(chosen), truncated=bool(POLLER.truncated), vpn_mbps=round(mbps, 2),
        window_s=int(ONLINE_WINDOW_S), as_of=POLLER.online_ref_iso(), source="panel-live",
    )
    return payload


async def cascade_users(ctx, target_uuid: str) -> dict | None:
    """Кто сейчас на нодах, каскадящих на ноду-цель. None — такой цели нет.

    Какой аутбаунд xray выбрал для конкретного юзера, панель не знает (это
    живёт только в access.log ноды), поэтому список — активные на
    нодах-источниках, с пометкой ``by_nodes``.
    """
    d = await collect(ctx)
    src = [n for n in d["nodes"] if target_uuid in (n.get("cascades") or [])]
    if not src:
        return None
    target = next((n for n in d["nodes"] if n["uuid"] == target_uuid), None)
    payload = {
        "kind": "cascade",
        "target": {"uuid": target_uuid, "name": (target or {}).get("name") or target_uuid},
        "nodes": [n["name"] for n in src],
        "by_nodes": True,
    }
    return await _nodes_users(ctx, {n["uuid"] for n in src}, payload)


async def exit_users(ctx, tag: str) -> dict | None:
    """Кто сейчас на нодах, у которых есть этот выход. None — выхода нет."""
    d = await collect(ctx)
    sink = next((s for s in d["sinks"] if s["tag"] == tag), None)
    if sink is None:
        return None
    src = [n for n in d["nodes"] if tag in (n.get("sinks") or [])]
    payload = {"kind": "exit", "sink": sink, "nodes": [n["name"] for n in src], "by_nodes": True}
    return await _nodes_users(ctx, {n["uuid"] for n in src}, payload)


GROUPS = ("mobile", "fixed", "cdn", "unknown", "all")


async def group_users(ctx, group: str) -> dict:
    """Сводный список активных юзеров группы по типу сети (все ноды).

    Только по живому опросу панели: без него класс по IP посчитать можно, а
    активных — нет (синк раз в 5 мин), поэтому отдаём пустой список с пометкой.
    """
    from .poller import POLLER

    if not POLLER.fresh:
        return {"group": group, "users": [], "count": 0, "window_s": int(ONLINE_WINDOW_S), "as_of": None, "source": "db-sync", "unavailable": True}
    act = POLLER.active_users()
    if group == "all":
        chosen = act
    else:
        cls = await _classify_users(ctx, [uid for uid, _ in act])
        chosen = [(uid, u) for uid, u in act if cls.get(str(uid), "unknown") == group]
    users = await _users_rows(ctx, POLLER, chosen, with_node=True)
    mbps = 0.0
    for uid, _ in chosen:
        mbps += (POLLER.user_bps(uid) or 0.0) * 8 / 1e6
    return {
        "group": group,
        "users": users,
        "count": len(chosen),
        "truncated": bool(POLLER.truncated),
        "vpn_mbps": round(mbps, 2),
        "window_s": int(ONLINE_WINDOW_S),
        "as_of": POLLER.online_ref_iso(),
        "source": "panel-live",
    }
