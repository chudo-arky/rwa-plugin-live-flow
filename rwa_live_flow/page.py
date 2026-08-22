"""Standalone-страница со схемой (``/ui``) — тонкая обёртка над тем же модулем.

Рендер один — ``module.MODULE_JS``; здесь только пустой документ и строка
монтирования. CSP бэкенда — ``script-src 'self'``: инлайн-скрипты панель
режет, поэтому JS отдаётся отдельным роутом ``/app`` того же origin (см.
routes.py); ссылка относительная (``src="app"``), чтобы пережить любой
префикс, под которым смонтирован плагин. Инлайн-стили разрешены
(``style-src 'unsafe-inline'``).

Палитра — фолбэки из модуля (тех же переменных темы, что у rw-admin, на
отдельной странице нет), поэтому тут задаём только фон и шрифт документа.
"""
from __future__ import annotations

from .module import MODULE_JS

PAGE_HTML = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Схема трафика</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; background: hsl(220 24% 7%); color: hsl(220 9% 84%);
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  .wrap { max-width: 1280px; margin: 0 auto; padding: 24px 20px 40px; }
</style>
</head>
<body>
<div class="wrap"><div id="lf-root"></div></div>
<script src="app" defer></script>
</body>
</html>
"""

# Модуль регистрирует window.rwaPluginUI.live_flow; standalone-страница тут же
# монтирует его в свой контейнер. <script defer> исполняется после разбора
# документа, контейнер к этому моменту есть.
APP_JS = MODULE_JS + r"""
(function () {
  var h = window.rwaPluginUI && window.rwaPluginUI.live_flow;
  var el = document.getElementById('lf-root');
  if (h && el) {
    h.mount(el);
    document.title = el.querySelector('.lf-h1') ? el.querySelector('.lf-h1').textContent : document.title;
  }
})();
"""
