"""Сбор живого среза: ноды с онлайном и трафиком + форма графа из конфиг-профилей."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
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
        # Ответ не той формы — не «профилей нет»: пустой набор лёг бы в кэш как
        # удачный, и каждой ноде достался бы выдуманный DIRECT.
        if not quiet:
            logger.warning("live_flow: config profiles response has unexpected shape")
        return None
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
            "cdn_declared": [str(i.get("tag")) for i in ins if isinstance(i, dict) and i.get("tag") and _inbound_declared_cdn(i)],
            "blind_inbounds": [str(i.get("tag")) for i in ins if isinstance(i, dict) and i.get("tag") and _inbound_blind(i)],
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


def _inbound_blind(ib: dict) -> bool:
    """Инбаунд, у которого Xray гарантированно пишет всех клиентов как 127.0.0.1.

    HTTP-транспорт на loopback (или unix-сокете) — значит перед ним обратный
    прокси, и без ``sockopt.trustedXForwardedFor`` Xray берёт адрес самого
    прокси. Проверено на Xray 26.7.28 (стенд 13.09.2026): предупреждение
    «trustedXForwardedFor is not configured; ignoring it», в access.log —
    127.0.0.1 у каждого. Следом слепнет всё: гео, ASN, деление по типу сети,
    а в карту онлайн-IP xray loopback не кладёт вовсе, так что и снимок
    панели адреса не даст. Исключение — PROXY protocol: с
    ``acceptProxyProtocol`` ядро видит настоящий адрес подключившегося.
    """
    ss = ib.get("streamSettings") if isinstance(ib.get("streamSettings"), dict) else {}
    if str(ss.get("network") or "tcp").lower() not in _CDN_NETWORKS:
        return False
    listen = str(ib.get("listen") or "").strip().lower()
    local = listen in ("127.0.0.1", "::1", "localhost") or listen.startswith(("/", "@", "127."))
    if not local:
        return False
    so = ss.get("sockopt") if isinstance(ss.get("sockopt"), dict) else {}
    return not so.get("trustedXForwardedFor") and not so.get("acceptProxyProtocol")


def _inbound_declared_cdn(ib: dict) -> bool:
    """Инбаунд, который владелец сам объявил входом через CDN.

    Метка — поле прямо в инбаунде конфиг-профиля::

        { "tag": "Moscow CDN", ..., "liveFlow": { "cdn": true } }

    Проверено 13.09.2026: Xray 26.7.28 принимает неизвестные поля
    (``xray run -test`` — Configuration OK), а панель сохраняет конфиг как есть
    (тело запроса — ``z.looseObject``, ``sortXrayConfig`` только переставляет
    ключи). Правка метки — это обновление инбаунда, а не пересоздание: панель
    узнаёт инбаунд по тегу, привязки хостов, сквадов и нод не рвутся.

    🔴 Не переименовывать для этого сам тег: для панели новое имя — удаление
    старого инбаунда и создание нового (хосты теряют привязку, из сквадов и с
    нод он удаляется каскадом).

    Доказательством метка не является: плагин верит владельцу. Проверить, что
    до инбаунда доходит только трафик CDN, по данным админки нельзя.
    """
    mark = ib.get("liveFlow")
    return isinstance(mark, dict) and mark.get("cdn") is True


def _cdn_mode(profiles: dict | None) -> str:
    """declared — хоть один инбаунд помечен владельцем; heuristic — меток нет.

    Как только владелец поставил метку, эвристика выключается на всей
    установке: помеченные входы — «через CDN», остальные — нет. Иначе рядом
    жили бы объявленные и угаданные входы, и группа врала бы наполовину.
    Без меток плагин ведёт себя как раньше — установки, где их не ставили,
    ничего не теряют.
    """
    return "declared" if any((p.get("cdn_declared") or []) for p in (profiles or {}).values()) else "heuristic"


def _cdn_tags(profiles: dict | None) -> set[str]:
    key = "cdn_declared" if _cdn_mode(profiles) == "declared" else "cdn_inbounds"
    return {t for p in (profiles or {}).values() for t in (p.get(key) or [])}


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


# ── Состояние агента ноды: есть ли он и читает ли access.log ───────
# Без этого схема на ноде без разбора лога говорила «агент ноды не сообщил IP»
# и не отличала «агента нет вовсе» от «агент жив, но access.log не читает».
AGENT_STALE_S = 300.0        # тем же порогом сама админка считает потухшим внешний сервер
AGENT_LOG_WINDOW_MIN = 30    # окно «приходил ли от ноды разбор access.log»
AGENT_STATE_TTL_S = 60.0
_agent_cache: dict = {"ts": 0.0, "map": None}


async def _log_seen_by_node(ctx) -> dict[str, set[str]]:
    """node_uuid → id пользователей, по которым агент дал строку.

    Единственный писатель таблицы — коллектор админки, поэтому строка с
    ``node_uuid = X`` доказывает, что агент X прислал разбор access.log.

    Считается и открытая строка, и новая за окно, и обе нужны. ``connected_at``
    пишется только при появлении новой пары (пользователь, IP) и потом не
    обновляется — это ключ партиционирования. На ноде с постоянным составом
    пользователей новых строк не будет часами, зато открытые висят: по одному
    лишь окну такая нода выглядела бы сломанной (поймано на боевой — ALA-01,
    пять открытых строк и ни одной новой за 67 минут).

    🔴 Но одной открытой строки мало в обратную сторону. Коллектор закрывает
    строки **только внутри батча от агента**, поэтому у агента, переставшего
    присылать подключения, они висят открытыми вечно: на боевой нашлась строка
    возрастом 5.6 суток. Сверять их с живой картиной панели нельзя — см.
    ``_log_alive``, — поэтому выключенный лог зависшие строки маскируют.

    Кэш на минуту: составного индекса ``(node_uuid, connected_at)`` в админке
    нет, и на большой базе GROUP BY может уйти в seq scan по текущей партиции,
    а ``/data`` дёргает каждая вкладка раз в 5 с. При сбое запроса держим
    прошлый ответ и всё равно сдвигаем ts — иначе будем долбить тяжёлым
    запросом каждые 5 с, пока база лежит.
    """
    import time as _time

    now = _time.time()
    c = _agent_cache
    if c["map"] is not None and now - c["ts"] < AGENT_STATE_TTL_S:
        return c["map"]
    try:
        rows = await ctx.db.fetch(
            """
            SELECT DISTINCT uc.node_uuid::text AS nu, u.id::text AS uid
            FROM user_connections uc
            JOIN users u ON u.uuid = uc.user_uuid
            WHERE uc.node_uuid IS NOT NULL
              AND (uc.disconnected_at IS NULL
                   OR uc.connected_at > now() - make_interval(mins => $1))
            """,
            AGENT_LOG_WINDOW_MIN,
        )
    except Exception:  # noqa: BLE001 — диагностика не важнее самой схемы
        ctx.logger.exception("live_flow: agent-state query failed")
        c["ts"] = now
        return c["map"] or {}
    out: dict[str, set[str]] = {}
    for r in rows:
        if r["nu"]:
            out.setdefault(str(r["nu"]), set()).add(str(r["uid"]))
    c.update(ts=now, map=out)
    return c["map"]


def _log_alive(agent_uids: set[str]) -> bool:
    """Есть ли по этой ноде разбор access.log. Снимок панели сюда намеренно не
    передаётся — и вот почему, чтобы никто не вернул это обратно не подумав.

    🔴 Сверять строки агента с тем, кого панель видит на ноде, НЕЛЬЗЯ:
    ``node_uuid`` в открытой строке переписывает любой отчитавшийся агент, а
    клиенты с авто-выбором пингуют все ноды подряд. Проверено на боевой
    12.09.2026: у AMS-01 панель показывала пользователей 16, 31, 35, 40, 44,
    50, 53, 87, а строки агента по той же ноде — 96, 99, 101; пересечения нет
    вовсе, хотя агент исправен. Плюс снимок панели отстаёт до полутора минут,
    и состояние начинало дрожать.

    Поэтому признак остаётся слабым и односторонним: строки есть — считаем, что
    разбор идёт. Цена — выключенный access.log на ноде так не определяется, пока
    у неё висят прежние открытые строки. Это ограничение данных админки, а не
    недосмотр: чтобы различать надёжно, нужна идентичность соединения с учётом
    ноды и сеанса, которой в ``user_connections`` нет.
    """
    return bool(agent_uids)


def _agent_state(metrics_age_s: float | None, users: int, log_seen: bool) -> str:
    """none | metrics_only | log | idle — что известно про агента ноды.

    ``metrics_only`` ставим ТОЛЬКО когда на ноде реально кто-то есть и при этом
    агент не показал по ней ни одной строки (см. ``_log_seen_by_node``): на
    пустой ноде сказать нечего, а ошибочный ярлык «сломан» хуже молчания.
    """
    if metrics_age_s is None or metrics_age_s > AGENT_STALE_S:
        return "none"
    if log_seen:
        return "log"
    return "metrics_only" if users > 0 else "idle"


async def collect(ctx) -> dict:
    """Срез на «сейчас»: числа онлайна берём у панели, они авторитетнее наших.

    Скорость VPN и живые onlineAt — из ``poller`` (опрос API панели каждые
    15 с); пока опрос не успел или упал — активные по синку БД (лаг до 5 мин),
    скорость VPN не показывается (UI падает на сетевую ↑/↓ агента).
    """
    from .connections import POLLER as CPOLLER
    from .metrics import POLLER as MPOLLER
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
               metrics_updated_at,
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

    log_seen = await _log_seen_by_node(ctx)
    now_utc = datetime.now(timezone.utc)

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
    # байты по тегу за окно метрик, сложенные по всему парку: из них доля выхода
    # «по парку» на карточке. Доля внутри ноды живёт в node["exit_shares"].
    fleet_bytes: dict[str, float] = {}

    snippets_unresolved: list[str] = []
    for row in rows:
        profile = (profiles or {}).get(_profile_uuid(row["raw_data"]) or "") or {}
        outbounds = _effective_outbounds(profile, profiles_available)
        for name in profile.get("snippets_unresolved") or []:
            if name not in snippets_unresolved:
                snippets_unresolved.append(name)

        node_sinks: list[str] = []
        cascades: list[str] = []
        # доли веток этой ноды за окно (None — мерить нечем, см. metrics.shares)
        msh = MPOLLER.shares(row["uuid"])
        shares = (msh or {}).get("shares") or {}
        exit_shares: dict[str, float] = {}
        casc_shares: dict[str, float] = {}
        casc_tags: dict[str, list[str]] = {}
        for outbound in outbounds:
            tag = outbound["tag"]
            proto = outbound["protocol"]
            # Каскад: аутбаунд-цепочка, ведущая на другую НАШУ ноду. Это не выход,
            # а прыжок — рисуем ребром нода→нода, в список выходов не кладём.
            target = _cascade_target(outbound.get("addr"), row["uuid"], addr_to_uuid, resolved) if proto in _CHAIN_PROTOCOLS else None
            share = shares.get(tag)
            if share is not None:
                fleet_bytes[tag] = fleet_bytes.get(tag, 0.0) + share * msh["bytes"]
            if target:
                if target not in cascades:
                    cascades.append(target)
                casc_tags.setdefault(target, []).append(tag)
                if share is not None:
                    casc_shares[target] = casc_shares.get(target, 0.0) + share
                continue
            kind = _SINK_KIND.get(proto, "chain")
            sink = {"tag": tag, "title": _SINK_TITLES.get(tag, tag), "kind": kind}
            if kind == "chain" and outbound.get("addr"):
                sink["addr"] = _norm_host(outbound.get("addr"))   # цепочка на чужой сервер — куда именно
            sinks.setdefault(tag, sink)
            node_sinks.append(tag)
            if share is not None:
                exit_shares[tag] = round(share, 4)

        users_now = int((POLLER.nodes.get(row["uuid"]) or {}).get("users_online", row["users_online"] or 0)) if live else int(row["users_online"] or 0)
        mu = row["metrics_updated_at"]
        metrics_age_s = (now_utc - mu).total_seconds() if mu else None
        nodes.append(
            {
                "uuid": row["uuid"],
                "name": row["name"],
                "position": row["position"],
                # счётчик ноды: живой из опроса панели, иначе из синка БД
                "users": users_now,
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
                # инбаунды, где адрес клиента не виден в принципе (см. _inbound_blind)
                "blind_inbounds": profile.get("blind_inbounds") or [],
                "sinks": node_sinks,
                "cascades": cascades,
                # диагностика агента: none | metrics_only | log | idle (см. _agent_state)
                "agent_state": _agent_state(
                    metrics_age_s, users_now,
                    _log_alive(log_seen.get(row["uuid"]) or set()),
                ),
                # доли трафика ноды по веткам за окно метрик: тег выхода → 0..1,
                # uuid ноды-цели каскада → 0..1. Пусто — измерений нет.
                "exit_shares": exit_shares,
                "cascade_shares": {u: round(v, 4) for u, v in casc_shares.items()},
                # теги аутбаундов, ведущих на эту ноду-цель: по ним видно,
                # кто из пользователей реально ушёл в этот каскад
                "cascade_tags": casc_tags,
                "metrics_window_s": (msh or {}).get("window_s"),
                "metrics_age_s": (None if metrics_age_s is None else round(metrics_age_s, 1)),
            }
        )

    fleet_total = sum(fleet_bytes.values())
    if fleet_total > 0:
        for tag, b in fleet_bytes.items():
            if tag in sinks:
                sinks[tag]["share"] = round(b / fleet_total, 4)
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
        # declared — группа CDN по меткам владельца в конфиге, heuristic — по признакам инбаунда
        "cdn_mode": _cdn_mode(profiles),
        "profiles_stale": bool(profiles_stale),
        # сниппеты, на которые ссылаются профили нод, но которых у панели нет:
        # ветки из них на схеме отсутствуют, UI показывает предупреждение
        "snippets_unresolved": snippets_unresolved,
        # источник цифр по веткам выходов: ok — доли посчитаны; иначе код ошибки
        # (metrics_unsupported | metrics_empty | metrics_timeout | metrics_unavailable)
        "metrics_error": MPOLLER.error,
        # источник IP: агент (user_connections) дополняется снимками панели там,
        # где агент access.log не читает. Код ошибки — только если опрос упал.
        "conn_error": CPOLLER.error,
        "conn_nodes": sum(1 for n in nodes if CPOLLER.ips(n["uuid"]) is not None),
        "metrics_age_s": (round(MPOLLER.age_s(), 1) if MPOLLER.age_s() is not None else None),
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


def _snapshot_taken_at(node_uuid: str):
    """Когда снят снимок панели по этой ноде, или None.

    🔴 Снимок отстаёт: обход нод идёт по кругу, и ему до полутора минут, тогда
    как агент шлёт батч каждые 30 секунд. Поэтому опровергать строку агента
    снимок вправе только если она СТАРШЕ него: иначе мы выбрасываем более
    свежие данные, а вместе с ними тег инбаунда — и пользователь, только что
    сменивший адрес, терял группу «Предположительно CDN».
    """
    from .connections import POLLER as CONN_POLLER

    age = CONN_POLLER.age_s(node_uuid or "")
    return None if age is None else datetime.now(timezone.utc) - timedelta(seconds=age)


def _row_outdated(row_ip, connected_at, live_ips: set, snap_at) -> bool:
    """Строка агента опровергнута снимком: её адреса в нём нет, и она старше него."""
    if not live_ips or snap_at is None or row_ip in live_ips:
        return False
    return connected_at is None or connected_at <= snap_at


async def _panel_ips(ctx, pairs) -> dict[str, tuple[str, dict | None]]:
    """``{id пользователя: (IP, строка ip_metadata | None)}`` из снимка панели.

    Дополняет ``user_connections`` там, где агент не разбирает access.log:
    xray держит карту онлайн-IP, и панель отдаёт её по ``by-node``
    (см. ``connections.py``). ``pairs`` — ``[(id, node_uuid)]``, обычно те
    пользователи, у которых строки в БД нет.

    🔴 Обогащения нет и не будет: ``ip_metadata`` только читается. У IP, до
    которого GeoIP ещё не дошёл, честно остаётся причина ``no_meta``.

    Приведение ``ip_address::text`` намеренное: в разных установках колонка
    бывает и VARCHAR, и INET. Индекс при этом не используется, но список тут
    короткий — только те, кого не нашли в ``user_connections``.
    """
    from .connections import POLLER as CONN_POLLER

    found: dict[str, str] = {}
    for uid, node_uuid in pairs:
        ip = CONN_POLLER.user_ip(node_uuid or "", uid)
        # 127.0.0.1 в карту xray не попадает вовсе, но приватный адрес мог
        # прийти из-за локального прокси — класс сети по нему всё равно никакой
        if ip and not _is_local_ip(ip):
            found[str(uid)] = ip
    if not found:
        return {}
    meta: dict[str, dict] = {}
    try:
        rows = await ctx.db.fetch(
            """
            SELECT ip_address::text AS ip, asn, asn_org, country_code, city,
                   is_mobile, connection_type,
                   (is_hosting OR is_vpn OR is_proxy OR is_tor) AS hosting,
                   is_hosting, is_vpn, is_proxy
            FROM ip_metadata WHERE ip_address::text = ANY($1::text[])
            """,
            sorted(set(found.values())),
        )
        meta = {r["ip"]: r for r in rows}
    except Exception:  # noqa: BLE001 — без гео список всё равно полезен
        ctx.logger.exception("live_flow: ip_metadata for panel IPs failed")
    return {uid: (ip, meta.get(ip)) for uid, ip in found.items()}


async def _classify_users(ctx, ids_str: list, node_of: dict | None = None) -> dict[str, str]:
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
    fresh = await _classify_users_db(ctx, missing, node_of or {})
    merged = dict(cached)
    merged.update(fresh)
    if not cached:
        _cls_cache["ts"] = now
    _cls_cache["map"] = merged
    return {u: merged.get(u, "unknown") for u in wanted}


async def _classify_users_db(ctx, ids_str: list, node_of: dict | None = None) -> dict[str, str]:
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
                   c.ip_address::text AS ip, c.connected_at, c.device_info->>'inbound_tag' AS inbound
            FROM users u
            LEFT JOIN LATERAL (
                SELECT c.ip_address, c.connected_at, c.device_info FROM user_connections c
                WHERE c.user_uuid = u.uuid
                  AND (c.disconnected_at IS NULL OR c.connected_at > now() - interval '10 minutes')
                ORDER BY c.connected_at DESC LIMIT 1
            ) c ON true
            LEFT JOIN ip_metadata m ON m.ip_address = c.ip_address
            WHERE u.id = ANY($1::bigint[])
            """,
            ids,
        )
        from .connections import POLLER as CONN_POLLER

        cdn_tags = _cdn_tags(_profiles_cache.get("data"))
        for r in rows:
            # Та же проверка свежести, что в списках: строка агента живёт в БД
            # открытой и после того, как человек ушёл с этого адреса. Без неё
            # тип сети считался по вчерашнему IP, и на ноде без разбора лога
            # деление бодро показывало «мобильный/Wi-Fi» там, где актуальный
            # адрес вообще не известен. Пропущенных тут подберёт снимок панели.
            node_uuid = (node_of or {}).get(str(r["id"])) or ""
            live_ips = set((CONN_POLLER.ips(node_uuid) or {}).get(str(r["id"])) or ())
            if _row_outdated(r["ip"], r["connected_at"], live_ips, _snapshot_taken_at(node_uuid)):
                continue
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
        # Кого не нашли в user_connections — пробуем снимком панели: на ноде без
        # разбора access.log это единственный источник IP.
        missing = [(str(u), (node_of or {}).get(str(u))) for u in ids_str if str(u) not in cls]
        for uid, (_ip, m) in (await _panel_ips(ctx, missing)).items():
            cls[uid] = "unknown" if m is None else _net_class(m["is_mobile"], m["connection_type"], bool(m["hosting"]))
            if cls[uid] == "unknown":
                _cls_why[uid] = "no_meta" if m is None else _unknown_why(True, True, False)
            else:
                _cls_why.pop(uid, None)
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
    cls = await _classify_users(ctx, [uid for uid, _ in act], {str(uid): u.get("node_uuid") for uid, u in act})
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
                   c.device_info->'outbound_tags' AS outbound,
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
    from .connections import POLLER as CONN_POLLER

    # Кого агент не показал — добираем снимком панели (Connections API)
    panel = await _panel_ips(ctx, [
        (uid, u.get("node_uuid")) for uid, u in live_users
        if not by_user.get(id2uuid.get(uid, ""))
    ])
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
        # 🔴 Открытая строка ≠ актуальная: коллектор закрывает строки только
        # внутри батча, поэтому у молчащего агента они висят сутками (на боевой
        # нашлась пятидневная). Когда панель даёт по этому пользователю список
        # адресов, он и есть текущий: строки агента с другими IP — прошлое.
        # Пустой список панели ничего не опровергает (127.0.0.1 в карту xray не
        # попадает), поэтому фильтруем только по непустому.
        live_ips = set((CONN_POLLER.ips(u.get("node_uuid") or "") or {}).get(str(uid)) or ())
        snap_at = _snapshot_taken_at(u.get("node_uuid") or "")
        if live_ips:
            rows_u = [r for r in rows_u if not _row_outdated(r["ip_address"], r["connected_at"], live_ips, snap_at)]
            seen_ips = {r["ip_address"] for r in rows_u}
            for extra in sorted(live_ips - seen_ips):
                panel.setdefault(str(uid), (extra, None))
        if not rows_u:
            got = panel.get(str(uid))
            if got is None and live_ips:
                got = (sorted(live_ips)[0], None)
            if got:
                ip, m = got
                users.append(dict(
                    base, ip=ip,
                    asn=(m or {}).get("asn"), as_name=(m or {}).get("asn_org"),
                    country=(m or {}).get("country_code"), city=(m or {}).get("city"),
                    mobile=(bool(m["is_mobile"]) if m and m["is_mobile"] is not None else None),
                    hosting=bool(m and (m["is_hosting"] or m["is_vpn"] or m["is_proxy"])),
                    # тега инбаунда в этом источнике нет — его знает только access.log
                    inbound=None, cdn=False, outbound=None, ip_since=None,
                    ip_source="panel",
                ))
                continue
            users.append(dict(base, ip=None, asn=None, as_name=None, country=None, city=None, mobile=None, hosting=False, inbound=None, outbound=None, ip_since=None))
            continue
        for r in rows_u:
            users.append(dict(
                base,
                ip=r["ip_address"], asn=r["asn"], as_name=r["asn_org"], country=r["country_code"], city=r["city"],
                mobile=(bool(r["is_mobile"]) if r["is_mobile"] is not None else None),
                hosting=bool(r["is_hosting"] or r["is_vpn"] or r["is_proxy"]),
                inbound=r["inbound"], cdn=r["inbound"] in _cdn_tags(_profiles_cache.get("data")),
                # аутбаунды из access.log; jsonb приходит списком, у агента до 1.8.3 — NULL
                outbound=_outbound_tags(r["outbound"]),
                ip_since=r["connected_at"].isoformat() if r["connected_at"] else None,
                ip_source="agent",
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


def _outbound_tags(value) -> list[str] | None:
    """``device_info->'outbound_tags'`` → список тегов или None.

    jsonb приходит то списком, то строкой: у asyncpg декодер json включён не
    везде, и полагаться на одну форму нельзя. None — агент поля не прислал
    (старая версия), пустой список — прислал, но аутбаундов в логе не было.
    """
    if isinstance(value, (list, tuple)):
        return [str(t) for t in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return None
        if isinstance(parsed, list):
            return [str(t) for t in parsed]
    return None


def _by_outbound(payload: dict, tags) -> dict:
    """Оставить в списке тех, кто реально ходил через эти аутбаунды.

    Работает, только когда агенты присылают ``outbound_tags`` (агент нод с
    1.8.3 при remnawave-admin от 4.8.3; у агентов постарше поля нет).
    Если ни у кого тегов нет — список остаётся прежним, «по нодам», и UI
    показывает прежнюю оговорку: соврать «никого» на старом агенте хуже, чем
    отдать более широкий список.

    На смешанном парке фильтруются только строки с тегами. Строка без них
    (агент старше 1.8.3, IP из снимка панели, IP нет вовсе) остаётся в списке,
    а её нода попадает в ``unverified_nodes``: по ней выбранный аутбаунд не
    виден, и выбросить человека значило бы соврать «через эту ветку не ходил».

    ⚠️ Это «за последние минуты человек ходил через эту ветку», а не «весь его
    трафик идёт туда»: за один батч один пользователь уходит в несколько веток
    сразу, а байтов по веткам access.log не содержит вовсе.
    """
    want = {t for t in (tags or ()) if t}
    rows = payload.get("users") or []
    if not want or not any(r.get("outbound") for r in rows):
        return payload
    kept, unverified = [], set()
    for r in rows:
        if r.get("outbound") is None:
            kept.append(r)
            unverified.add(r.get("node") or r.get("node_uuid") or "?")
        elif want & set(r["outbound"]):
            kept.append(r)
    payload["users"] = kept
    payload["count"] = len({(r.get("user"), r.get("node_uuid")) for r in kept})
    payload["by_nodes"] = False
    payload["by_outbound"] = True
    payload["unverified_nodes"] = sorted(unverified)
    return payload


async def cascade_users(ctx, target_uuid: str) -> dict | None:
    """Кто сейчас на нодах, каскадящих на ноду-цель. None — такой цели нет.

    Если агенты присылают ``outbound_tags``, список сужается до тех, кто
    действительно ушёл в этот каскад (``by_outbound``). Без них остаётся
    прежнее поведение — все активные на нодах-источниках (``by_nodes``).
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
    tags = [t for n in src for t in (n.get("cascade_tags") or {}).get(target_uuid, [])]
    return _by_outbound(await _nodes_users(ctx, {n["uuid"] for n in src}, payload), tags)


async def exit_users(ctx, tag: str) -> dict | None:
    """Кто сейчас на нодах, у которых есть этот выход. None — выхода нет."""
    d = await collect(ctx)
    sink = next((s for s in d["sinks"] if s["tag"] == tag), None)
    if sink is None:
        return None
    src = [n for n in d["nodes"] if tag in (n.get("sinks") or [])]
    payload = {"kind": "exit", "sink": sink, "nodes": [n["name"] for n in src], "by_nodes": True}
    return _by_outbound(await _nodes_users(ctx, {n["uuid"] for n in src}, payload), [tag])


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
        cls = await _classify_users(ctx, [uid for uid, _ in act], {str(uid): u.get("node_uuid") for uid, u in act})
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
