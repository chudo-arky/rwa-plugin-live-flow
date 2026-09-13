"""Live Flow — живая схема трафика (Plugin API v1).

Рисует поток «пользователи → ноды → аутбаунды» в реальном времени: толщина
линии и число в кружке — количество онлайн-пользователей на ноде, бег
пунктира — наличие реального трафика.

Форма графа берётся из конфиг-профилей панели, а не выдумывается: как только
у профиля появится WARP или цепочка на другой сервер, соответствующий блок
встанет на схему сам. Линия к ветке появляется, когда по её счётчику в
панели за последние минуты реально прошёл трафик (см. metrics.py); какой
аутбаунд выбран для конкретного пользователя, видно только из access.log
ноды — через агента админки.

Импорты из ``web.backend.*`` отложены внутрь функций, чтобы пакет
импортировался в изоляции.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

PLUGIN_ID = "live_flow"
PLUGIN_NAME = "Живая схема трафика"
DIST_NAME = "rwa-plugin-live-flow"


def _own_version() -> str:
    """Версия — из метаданных установленного пакета, а не константой рядом.

    Вторая константа неизбежно разъезжается с pyproject: так уже вышли два
    разных сборочных артефакта под одним номером. Источник правды — сам wheel.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version(DIST_NAME)
    except PackageNotFoundError:  # запуск из исходников, не из wheel
        return "0.0.0"


__version__ = _own_version()


def _build(ctx):
    from web.backend.core.plugins import PluginParts, ScheduledTask

    from .connections import INTERVAL_S as CONN_INTERVAL_S
    from .connections import POLLER as CONN_POLLER
    from .metrics import INTERVAL_S as METRICS_INTERVAL_S
    from .metrics import POLLER as METRICS_POLLER
    from .poller import INTERVAL_S, POLLER
    from .routes import build_router

    async def poll_tick() -> None:
        await POLLER.tick(ctx.logger)

    async def metrics_tick() -> None:
        await METRICS_POLLER.tick(ctx.logger)

    async def connections_tick() -> None:
        # список нод берём из среза панели: опрашивать отключённые незачем
        await CONN_POLLER.tick(POLLER.nodes, ctx.logger)

    return PluginParts(
        router=build_router(ctx),
        # Опрос панели: скорость VPN по счётчикам xray и живой онлайн (см. poller.py).
        scheduled_tasks=[
            ScheduledTask(name="panel-poll", interval_seconds=INTERVAL_S, coro=poll_tick),
            # Байты по веткам выходов — отдельной задачей: свой backoff и свой код
            # ошибки, чтобы сбой метрик не морозил основную схему (см. metrics.py).
            ScheduledTask(name="metrics-poll", interval_seconds=METRICS_INTERVAL_S, coro=metrics_tick),
            # IP пользователей там, где агент не читает access.log (см. connections.py)
            ScheduledTask(name="connections-sweep", interval_seconds=CONN_INTERVAL_S, coro=connections_tick),
        ],
    )


def _ui_kwargs() -> dict:
    """Объявить страницу для generic-маршрута, если админка его умеет.

    ``PluginUI`` появился в remnawave-admin 4.5.4 вместе с маршрутом
    ``/plugins/:pluginId`` (PR #267). На старых версиях класса нет — тогда
    ничего не объявляем: остаётся пункт меню и standalone-страница ``/ui``.
    """
    try:
        from web.backend.core.plugins import PluginUI
    except ImportError:
        return {}
    return {"ui": PluginUI(kind="module", path="/ui-module")}


def manifest():
    from web.backend.core.plugins import NavEntry, PluginManifest

    # label_i18n — намеренно человеческий текст, а не ключ: переводы плагинов
    # лежат во фронтенд-бандле, свой ключ туда не добавить без форка, а
    # i18next при отсутствии перевода возвращает сам ключ, то есть подпись.
    # icon — только из ICON_MAP (web/frontend/src/lib/plugins.ts); произвольное
    # имя фронт не подхватит и нарисует пусто.
    return PluginManifest(
        id=PLUGIN_ID,
        name=PLUGIN_NAME,
        version=__version__,
        api_version=1,
        billing="free",
        build=_build,
        # view — схема и агрегаты; view_users — списки людей (логин, IP, AS, Telegram ID, гео)
        rbac_resources={"live_flow": ["view", "view_users"]},
        navigation=[
            NavEntry(
                path="/plugins/live-flow",
                label_i18n="Схема трафика",
                icon="Globe",
                permission=("live_flow", "view"),
                section_i18n="nav.sections.plugins",
            ),
        ],
        **_ui_kwargs(),
    )
