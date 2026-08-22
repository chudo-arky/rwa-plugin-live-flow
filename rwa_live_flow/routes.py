"""Роуты плагина.

Авторизацию плагин объявляет сам: загрузчик вешает на роутер только гейт
лицензии, и то лишь платным плагинам. Без явной зависимости ручки были бы
открыты всем, кто дотянулся до бэкенда.
"""
from __future__ import annotations

import re

from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

# Персональные данные (IP, логины, Telegram ID) не должны оседать в кэшах
# браузера и прокси — все JSON-ответы отдаём с no-store.
_NO_STORE = {"Cache-Control": "private, no-store", "Pragma": "no-cache"}


def _json(payload: dict, status: int = 200) -> JSONResponse:
    """JSONResponse с no-store. jsonable_encoder обязателен: прямой JSONResponse
    минует кодировщик FastAPI, а из БД могут прийти IPv4Address/datetime."""
    return JSONResponse(jsonable_encoder(payload), status_code=status, headers=_NO_STORE)

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def build_router(ctx):
    from fastapi import APIRouter, Depends, HTTPException
    from fastapi.responses import HTMLResponse, Response

    from web.backend.core.plugin_api import auth_deps

    from .data import GROUPS, collect, group_users, node_users
    from .module import MODULE_JS
    from .page import APP_JS, PAGE_HTML

    AdminUser, require_permission = auth_deps()
    router = APIRouter()

    async def _can_view_users(admin) -> bool | None:
        """Есть ли у текущего админа live_flow:view_users — чтобы UI не предлагал клик,
        который упрётся в 403. None — определить не удалось (UI оставит как есть)."""
        try:
            from shared.rbac import has_permission

            return bool(await has_permission(getattr(admin, "role_id", None), "live_flow", "view_users"))
        except Exception:  # noqa: BLE001
            return None

    @router.get("/data", summary="Живой срез: ноды, онлайн, трафик, форма графа (live_flow:view)")
    async def data(
        admin: AdminUser = Depends(require_permission("live_flow", "view")),
    ):
        payload = await collect(ctx)
        payload["can_view_users"] = await _can_view_users(admin)
        return _json(payload)

    # Списки людей (логин, IP, AS, Telegram ID, гео) — отдельное право
    # live_flow:view_users: просмотр схемы его не даёт.
    @router.get("/node/{node_uuid}/users", summary="Кто сейчас на ноде: пользователь, IP, AS (live_flow:view_users)")
    async def node_users_route(
        node_uuid: str,
        _admin: AdminUser = Depends(require_permission("live_flow", "view_users")),
    ):
        if not _UUID_RE.match(node_uuid):
            raise HTTPException(status_code=422, detail={"code": "bad_uuid"})
        data = await node_users(ctx, node_uuid)
        if data is None:
            raise HTTPException(status_code=404, detail={"code": "node_not_found"})
        return _json(data)

    @router.get("/group/{group}/users", summary="Сводный список активных по типу сети: mobile | fixed | unknown | all (live_flow:view_users)")
    async def group_users_route(
        group: str,
        _admin: AdminUser = Depends(require_permission("live_flow", "view_users")),
    ):
        if group not in GROUPS:
            raise HTTPException(status_code=422, detail={"code": "bad_group"})
        return _json(await group_users(ctx, group))

    @router.get("/ui", response_class=HTMLResponse, summary="Страница со схемой")
    async def ui(
        _admin: AdminUser = Depends(require_permission("live_flow", "view")),
    ):
        return HTMLResponse(PAGE_HTML)

    @router.get("/app", summary="JS страницы (CSP script-src 'self'; без .js — его перехватывает статик-локация nginx фронта)")
    async def app_js(
        _admin: AdminUser = Depends(require_permission("live_flow", "view")),
    ):
        return Response(APP_JS, media_type="application/javascript; charset=utf-8")

    @router.get("/ui-module", summary="UI-модуль для generic-маршрута /plugins/:pluginId (window.rwaPluginUI)")
    async def ui_module(
        _admin: AdminUser = Depends(require_permission("live_flow", "view")),
    ):
        # Без расширения .js — иначе перехватит статик-локация nginx фронта.
        # Авторизация — кукой rw_access: <script src> того же origin её шлёт.
        return Response(MODULE_JS, media_type="application/javascript; charset=utf-8")

    return router
