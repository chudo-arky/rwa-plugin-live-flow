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
    out: dict[str, dict] = {}
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
        if not isinstance(cfg, dict):
            cfg = {}
        outs = cfg.get("outbounds") if isinstance(cfg.get("outbounds"), list) else []
        ins = cfg.get("inbounds") if isinstance(cfg.get("inbounds"), list) else []
        out[str(p.get("uuid"))] = {
            "name": p.get("name"),
            "outbounds": [
                {"tag": str(o.get("tag")), "protocol": str(o.get("protocol") or ""), "addr": _outbound_addr(o)}
                for o in outs
                if isinstance(o, dict) and o.get("tag")
            ],
            "inbounds": [str(i.get("tag")) for i in ins if isinstance(i, dict) and i.get("tag")],
        }
    return out


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
    total_split = {"mobile": 0.0, "fixed": 0.0, "unknown": 0.0, "mobile_users": 0, "fixed_users": 0, "unknown_users": 0}
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

    # адрес ноды (домен) → uuid: по нему ловим каскад (аутбаунд на нашу же ноду)
    addr_to_uuid = {
        str(r["address"]).strip().lower(): r["uuid"]
        for r in rows
        if r["address"]
    }

    sinks: dict[str, dict] = {}
    nodes: list[dict] = []

    for row in rows:
        profile = (profiles or {}).get(_profile_uuid(row["raw_data"]) or "") or {}
        if profiles_available:
            # DIRECT по умолчанию — только когда профили получены, но у этой ноды
            # профиля нет или он пуст. При упавшем запросе выходы не рисуем вовсе.
            outbounds = profile.get("outbounds") or [{"tag": "DIRECT", "protocol": "freedom"}]
        else:
            outbounds = []

        node_sinks: list[str] = []
        cascades: list[str] = []
        for outbound in outbounds:
            tag = outbound["tag"]
            proto = outbound["protocol"]
            addr = (outbound.get("addr") or "").strip().lower()
            # Каскад: аутбаунд-цепочка, ведущая на другую НАШУ ноду. Это не выход,
            # а прыжок — рисуем ребром нода→нода, в список выходов не кладём.
            if proto in _CHAIN_PROTOCOLS and addr in addr_to_uuid and addr_to_uuid[addr] != row["uuid"]:
                target = addr_to_uuid[addr]
                if target not in cascades:
                    cascades.append(target)
                continue
            kind = _SINK_KIND.get(proto, "chain")
            sinks.setdefault(
                tag,
                {"tag": tag, "title": _SINK_TITLES.get(tag, tag), "kind": kind},
            )
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


def _net_class(is_mobile, connection_type) -> str:
    """mobile | fixed | unknown по ip_metadata (is_mobile / connection_type)."""
    if is_mobile is True or (connection_type or "").lower() == "mobile":
        return "mobile"
    if is_mobile is False or connection_type:
        return "fixed"
    return "unknown"


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
            SELECT u.id, m.is_mobile, m.connection_type
            FROM users u
            LEFT JOIN LATERAL (
                SELECT c.ip_address FROM user_connections c
                WHERE c.user_uuid = u.uuid
                  AND (c.disconnected_at IS NULL OR c.connected_at > now() - interval '10 minutes')
                ORDER BY c.connected_at DESC LIMIT 1
            ) c ON true
            LEFT JOIN ip_metadata m ON m.ip_address = c.ip_address
            WHERE u.id = ANY($1::bigint[])
            """,
            ids,
        )
        for r in rows:
            cls[str(r["id"])] = _net_class(r["is_mobile"], r["connection_type"])
        for u in ids_str:
            cls.setdefault(str(u), "unknown")
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
        return {}, {"mobile": 0.0, "fixed": 0.0, "unknown": 0.0, "mobile_users": 0, "fixed_users": 0, "unknown_users": 0}
    cls = await _classify_users(ctx, [uid for uid, _ in act])
    def blank():
        return {"mobile": 0.0, "fixed": 0.0, "unknown": 0.0, "mobile_users": 0, "fixed_users": 0, "unknown_users": 0}
    per_node: dict[str, dict] = {}
    total = blank()
    for uid, u in act:
        nu = u.get("node_uuid")
        k = cls.get(str(uid), "unknown")
        bps = poller.user_bps(str(uid)) or 0.0
        mbps = bps * 8 / 1e6
        total[k] += mbps
        total[k + "_users"] += 1
        if nu:
            d = per_node.setdefault(nu, blank())
            d[k] += mbps
            d[k + "_users"] += 1
    for d in list(per_node.values()) + [total]:
        for k in ("mobile", "fixed", "unknown"):
            d[k] = round(d[k], 2)
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
                inbound=r["inbound"],
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


GROUPS = ("mobile", "fixed", "unknown", "all")


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
