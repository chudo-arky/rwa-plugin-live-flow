"""JS-модуль схемы — единственный рендер плагина.

Его грузит generic-маршрут админки (``/plugins/:pluginId`` → ``/ui-module``,
контракт ``window.rwaPluginUI[<id>] = {mount, unmount}``), и он же лежит в
основе standalone-страницы (``/app`` = этот модуль + строка монтирования,
см. ``page.py``). DOM админки не трогает: контейнер выдаёт она сама.
"""

MODULE_JS = r"""// live_flow: UI-модуль (generic-маршрут админки /plugins/:pluginId и standalone /ui).
//
// Контракт: window.rwaPluginUI['live_flow'] = { mount(el), unmount() }.
// Админка (ExternalPluginPage) грузит этот скрипт с api_prefix + ui.path и
// вызывает mount с контейнером внутри родного layout — сайдбар, шапка и
// крошки достаются даром, DOM админки не трогаем.
(function () {
  var PLUGIN_ID = 'live_flow';
  var VIEW_ID = 'suptaz-live-flow-view';
  // База API — из адреса самого скрипта: так переживаем SECRET_PATH и любой
  // префикс, под которым админка смонтировала плагин. Запасной путь — дефолт.
  var SRC = (document.currentScript && document.currentScript.src) || '';
  var M = SRC.match(/^(.*)\/(ui-module|app)(\?.*)?$/);
  var API_BASE = M ? M[1] : '/api/v2/plugins/live_flow';
  var DATA_URL = API_BASE + '/data';
  var REFRESH_MS = 5000, DASH_MS = 1100;
  var timer = null, langTimer = null, panelTimer = null, resizeFn = null, keyFn = null;
  var L = {
    ru: {
      title: 'Схема трафика', sub: 'Живой поток: пользователи → ноды → выход · клик по ноде — кто на ней сейчас', subNoUsers: 'Живой поток: пользователи → ноды → выход',
      now: 'Сейчас в сети', loading: 'загрузка…', updated: 'обновлено ', nodata: 'нет данных: ',
      online: ' онлайн', nodesCnt: ' нод',
      capUsers: 'ПОЛЬЗОВАТЕЛИ', capNodes: 'НОДЫ', capCascade: 'КАСКАД', capExit: 'ВЫХОД',
      users: 'Пользователи', noUsers: 'нет пользователей', mbps: ' Мбит/с', ppl: ' чел.', active: ' активных', activeTip: 'активных по панели', vpn: 'VPN ⇅ ', net: 'сеть хоста', liveSrc: 'панель live', dbSrc: 'синк БД (до 5 мин)', mob: 'мобильный', fix: 'Wi-Fi/LAN', unk: 'сеть неизвестна', lgSplit: 'линии от групп слева: ', mobBox: 'Мобильная сеть', fixBox: 'Wi-Fi / LAN', unkBox: 'Сеть неизвестна', allBox: 'Пользователи', zIn: 'приблизить', zOut: 'отдалить', zReset: 'сбросить масштаб', zHint: 'колесо мыши — масштаб, перетаскивание — сдвиг', thNode: 'Нода', pGroup: 'Активные: ', pNoLive: 'живого опроса панели сейчас нет — сводный список по группам недоступен', pTrunc: 'срез панели неполный (юзеров больше лимита опроса)', pollErr: ' · опрос панели: ошибка', pollTimeout: ' · опрос панели: таймаут',
      internet: 'Интернет', blocked: 'Блокировка', toNet: 'выход в сеть', noMeasure: 'нет измерений',
      lgLive: 'идёт VPN-трафик (счётчики xray панели) — пунктир бежит', lgIdle: 'подключены, но молчат',
      lgBadge: 'в карточке ноды справа: реально активных по панели · счётчик ноды (с пингами авто-выбора)',
      offline: 'нет связи с нодой', profile: 'профиль', inbounds: 'инбаунды',
      noProfiles: 'конфигурация выходов недоступна — выходы не показаны',
      noteA: 'ветки ', noteB: ' есть в конфиге, но чисел по ним у панели нет',
      pUsers: 'Пользователи на ноде', pSeen: 'по панели активны ', pOf: ' · счётчик ноды ', pByPanel: ' (с пингами авто-выбора)', asOf: 'срез панели ',
      pEmptyA: 'по панели за последние ', pEmptyB: ' мин на этой ноде никто не был активен; счётчик ноды считает и пинги клиентов с авто-выбором серверов',
      pNone: 'сейчас никого', pErr: 'не удалось загрузить: ', pClose: 'закрыть',
      thUser: 'Пользователь', thIp: 'IP', thAs: 'AS', thGeo: 'гео', thSince: 'Активен',
      mobile: 'моб.', hosting: 'хостинг/VPN', inbound: 'инбаунд'
    },
    en: {
      title: 'Traffic flow', sub: 'Live flow: users → nodes → exit · click a node to see who is on it', subNoUsers: 'Live flow: users → nodes → exit',
      now: 'Online now', loading: 'loading…', updated: 'updated ', nodata: 'no data: ',
      online: ' online', nodesCnt: ' nodes',
      capUsers: 'USERS', capNodes: 'NODES', capCascade: 'CASCADE', capExit: 'EXIT',
      users: 'Users', noUsers: 'no users', mbps: ' Mbps', ppl: ' ppl', active: ' active', activeTip: 'active per panel', vpn: 'VPN ⇅ ', net: 'host NIC', liveSrc: 'panel live', dbSrc: 'DB sync (up to 5 min)', mob: 'mobile', fix: 'Wi-Fi/LAN', unk: 'unknown network', lgSplit: 'lines from the groups on the left: ', mobBox: 'Mobile network', fixBox: 'Wi-Fi / LAN', unkBox: 'Unknown network', allBox: 'Users', zIn: 'zoom in', zOut: 'zoom out', zReset: 'reset zoom', zHint: 'mouse wheel — zoom, drag — pan', thNode: 'Node', pGroup: 'Active: ', pNoLive: 'no live panel poll right now — group lists are unavailable', pTrunc: 'panel snapshot is truncated (more users than the poll limit)', pollErr: ' · panel poll: error', pollTimeout: ' · panel poll: timeout',
      internet: 'Internet', blocked: 'Blocked', toNet: 'to the internet', noMeasure: 'not measured',
      lgLive: 'VPN traffic flowing (panel xray counters) — dashes move', lgIdle: 'connected but idle',
      lgBadge: 'on the node card, right: really active per panel · node counter (incl. auto-select probes)',
      offline: 'node unreachable', profile: 'profile', inbounds: 'inbounds',
      noProfiles: 'exit config unavailable — exits are hidden',
      noteA: 'branches ', noteB: ' exist in the config, but the panel has no numbers for them',
      pUsers: 'Users on the node', pSeen: 'active per panel ', pOf: ' · node counter ', pByPanel: ' (incl. auto-select probes)', asOf: 'panel snapshot ',
      pEmptyA: 'per panel nobody was active on this node in the last ', pEmptyB: ' min; the node counter also counts probes from clients with server auto-select',
      pNone: 'nobody right now', pErr: 'failed to load: ', pClose: 'close',
      thUser: 'User', thIp: 'IP', thAs: 'AS', thGeo: 'geo', thSince: 'Active',
      mobile: 'mobile', hosting: 'hosting/VPN', inbound: 'inbound'
    }
  };
  function lang() {
    var v = '';
    try { v = (localStorage.getItem('i18nextLng') || '').toLowerCase(); } catch (e) { v = ''; }
    if (!v) v = (navigator.language || 'ru').toLowerCase();
    return v.indexOf('en') === 0 ? 'en' : 'ru';   // fallbackLng у админки — ru
  }
  function t() { return L[lang()]; }
  function locale() { return lang() === 'en' ? 'en-GB' : 'ru-RU'; }
  function sinkTitle(sk, manyInternet) {
    // При нескольких internet-выходах общее «Интернет» их не различает — показываем тег
    if (sk.kind === 'internet') return manyInternet ? (sk.title || sk.tag) : t().internet;
    if (sk.kind === 'block') return t().blocked;
    return sk.title || sk.tag;
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }
  function widthFor(u, max) { return u ? 1.0 + (u / Math.max(max, 1)) * 3.2 : 0.8; }

  var ICONS = {
    users: '<path d="M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/>',
    node: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 6h.01"/><path d="M6 18h.01"/>',
    internet: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>',
    block: '<circle cx="12" cy="12" r="10"/><path d="M4.93 4.93l14.14 14.14"/>',
    warp: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    chain: '<path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>',
    mobile: '<rect x="5" y="2" width="14" height="20" rx="2"/><path d="M12 18h.01"/>',
    wifi: '<path d="M5 12.55a11 11 0 0114.08 0"/><path d="M1.42 9a16 16 0 0121.16 0"/><path d="M8.53 16.11a6 6 0 016.95 0"/><path d="M12 20h.01"/>',
    unknown: '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>'
  };
  function ico(kind, x, y) {
    var p = ICONS[kind];
    return p ? '<g class="lf-ico" transform="translate(' + x + ',' + y + ') scale(0.75)">' + p + '</g>' : '';
  }

  // Кубическая Безье с горизонтальными касательными на концах — та же кривая,
  // что рисует edge(); bezPt даёт точку на ней, чтобы бейдж ложился НА линию.
  function edge(x0, y0, x1, y1) {
    var mx = (x0 + x1) / 2;
    return 'M ' + x0 + ' ' + y0 + ' C ' + mx + ' ' + y0 + ', ' + mx + ' ' + y1 + ', ' + x1 + ' ' + y1;
  }
  function bezPt(x0, y0, x1, y1, k) {
    var mx = (x0 + x1) / 2, u = 1 - k;
    var a = u * u * u, b = 3 * u * u * k, c = 3 * u * k * k, d = k * k * k;
    return { x: a * x0 + b * mx + c * mx + d * x1, y: a * y0 + b * y0 + c * y1 + d * y1 };
  }
  // Концы линий раскладываем по высоте карточки, а не сводим в одну точку:
  // порт i из n в коробке высотой h с центром cy.
  function port(cy, h, i, n) {
    if (n <= 1) return cy;
    var pad = Math.min(12, h / 4), span = h - pad * 2;
    return cy - h / 2 + pad + (span * i) / (n - 1);
  }
  // Фаза бега пунктира привязана к часам, а не к моменту перерисовки: SVG
  // пересобирается каждые 5 с, и без этого пунктир дёргался бы на каждом тике.
  function phase() { return ' style="animation-delay:-' + (Date.now() % DASH_MS) + 'ms"'; }
  function isLive(n) { return n.connected && n.users > 0 && (n.vpn_mbps != null ? n.vpn_mbps > 0 : (n.tx_mbps > 0 || n.rx_mbps > 0)); }
  function byY(pos) { return function (a, b) { return pos['n:' + a.uuid].y - pos['n:' + b.uuid].y; }; }

  function splitText(sp) {
    if (!sp) return '';
    var parts = [];
    if (sp.mobile || sp.mobile_users) parts.push(t().mob + ' ' + (sp.mobile || 0).toFixed(2) + t().mbps + ' (' + (sp.mobile_users || 0) + ')');
    if (sp.fixed || sp.fixed_users) parts.push(t().fix + ' ' + (sp.fixed || 0).toFixed(2) + t().mbps + ' (' + (sp.fixed_users || 0) + ')');
    if (sp.unknown || sp.unknown_users) parts.push(t().unk + ' ' + (sp.unknown || 0).toFixed(2) + t().mbps + ' (' + (sp.unknown_users || 0) + ')');
    return parts.join(' · ');
  }

  function renderSvg(d, selected) {
    var nodes = (d.nodes || []).slice().sort(function (a, b) {
      // Порядок как в панели Remnawave (viewPosition); без позиции — в конец по
      // имени. Стабильный: сортировка по онлайну тасовала бы карточки каждые 5 с.
      var pa = (a.position == null) ? Infinity : a.position, pb = (b.position == null) ? Infinity : b.position;
      if (pa !== pb) return pa < pb ? -1 : 1;
      return String(a.name || '').localeCompare(String(b.name || ''));
    });
    var sinks = d.sinks || [];
    var maxUsers = Math.max.apply(null, [1].concat(nodes.map(function (n) { return n.users; })));
    var NH = 56, STEP = 72, TOP = 34, nodeW = 250, userX = 40, userW = 230, userH = 66, sinkW = 178;   // userW: «15 активных · 19.62 Мбит/с» должно влезать
    var TXT = 44;   // отступ текста от левого края карточки: иконка + зазор

    // Каскад раскладывает граф в 4 колонки: нода-цель уезжает в отдельный ряд
    // правее (две линии: синяя от юзеров + янтарная от источника), выходы ещё
    // правее, масштаб мельче (шире viewBox).
    var targets = {};
    nodes.forEach(function (n) { (n.cascades || []).forEach(function (u) { targets[u] = true; }); });
    var cascNodes = nodes.filter(function (n) { return targets[n.uuid]; });
    var mainNodes = nodes.filter(function (n) { return !targets[n.uuid]; });
    var hasCasc = cascNodes.length > 0;

    var nodeX = 420, cascX = 830;
    var sinkX = hasCasc ? 1230 : 830;
    var W = hasCasc ? 1450 : 1050;

    var mainRows = Math.max(mainNodes.length, 2);
    var centerY = (TOP + (TOP + mainRows * STEP)) / 2;

    var pos = {};
    mainNodes.forEach(function (n, i) { pos['n:' + n.uuid] = { x: nodeX, y: TOP + i * STEP + NH / 2 }; });
    var cascTop = TOP + Math.max(0, mainNodes.length - cascNodes.length) * STEP / 2;
    cascNodes.forEach(function (n, j) { pos['n:' + n.uuid] = { x: cascX, y: cascTop + j * STEP + NH / 2 }; });

    var live = sinks.filter(function (s) { return s.kind === 'internet'; });
    var other = sinks.filter(function (s) { return s.kind !== 'internet'; });
    var ordered = live.concat(other);
    var sinkTotalH = ordered.length ? ordered.length * NH + (ordered.length - 1) * 24 : 0;
    var sinkTop = Math.max(TOP, centerY - sinkTotalH / 2);
    ordered.forEach(function (sk, i) { pos['s:' + sk.tag] = { x: sinkX, y: sinkTop + i * (NH + 24) + NH / 2 }; });

    var H = Math.max(TOP + mainRows * STEP, cascTop + cascNodes.length * STEP, sinkTop + sinkTotalH) + 34;

    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMin meet">';
    s += '<text class="lf-cap" x="' + userX + '" y="18">' + t().capUsers + '</text>';
    s += '<text class="lf-cap" x="' + nodeX + '" y="18">' + t().capNodes + '</text>';
    if (hasCasc) s += '<text class="lf-cap" x="' + cascX + '" y="18">' + t().capCascade + '</text>';
    if (ordered.length) s += '<text class="lf-cap" x="' + sinkX + '" y="18">' + t().capExit + '</text>';

    // Источники слева: при живом делении — группы по типу сети юзера
    // (мобильная / Wi-Fi-LAN / неизвестно), иначе одна карточка «Пользователи».
    var tot = d.vpn_split_total;
    var classes = tot
      ? [{ k: 'mobile', cls: 'm', icon: 'mobile', title: t().mobBox, users: tot.mobile_users || 0, mbps: tot.mobile || 0 },
         { k: 'fixed', cls: 'f', icon: 'wifi', title: t().fixBox, users: tot.fixed_users || 0, mbps: tot.fixed || 0 }]
      : [{ k: 'all', cls: 'a', icon: 'users', title: t().users, users: (d.total_active != null ? d.total_active : (d.total_users || 0)), mbps: null }];
    if (tot && (tot.unknown_users || 0) > 0) classes.push({ k: 'unknown', cls: 'u', icon: 'unknown', title: t().unkBox, users: tot.unknown_users || 0, mbps: tot.unknown || 0 });
    var boxGap = 18, colH = classes.length * userH + (classes.length - 1) * boxGap, top0 = centerY - colH / 2;
    classes.forEach(function (c, i) { c.y = top0 + i * (userH + boxGap) + userH / 2; });
    function cUsers(n, c) { return c.k === 'all' ? n.users : (((n.vpn_split || {})[c.k + '_users']) || 0); }
    function cMbps(n, c) {
      if (c.k === 'all') return n.vpn_mbps != null ? n.vpn_mbps : (n.tx_mbps + n.rx_mbps);
      return ((n.vpn_split || {})[c.k]) || 0;
    }
    // Линии группа → нода: только к нодам на связи, где у этой группы кто-то есть.
    var srcEdges = [], incoming = {}, maxClassUsers = 1;
    classes.forEach(function (c) {
      c.targets = nodes.filter(function (n) { return pos['n:' + n.uuid] && n.connected && cUsers(n, c) > 0; }).sort(byY(pos));
      c.targets.forEach(function (n) { maxClassUsers = Math.max(maxClassUsers, cUsers(n, c)); });
    });
    classes.forEach(function (c) {
      c.targets.forEach(function (n, i) {
        (incoming[n.uuid] = incoming[n.uuid] || []).push({ c: c, y0: port(c.y, userH, i, c.targets.length) });
      });
    });
    nodes.forEach(function (n) {
      var p = pos['n:' + n.uuid], inc = incoming[n.uuid];
      if (!p || !inc) return;
      inc.forEach(function (e, j) {
        srcEdges.push({ n: n, c: e.c, d: [userX + userW, e.y0, p.x, port(p.y, NH, j, inc.length)] });
      });
    });
    // Ноды, которым рисуем бейдж и линию к выходу: на связи и кто-то онлайн по счётчику.
    var active = nodes.filter(function (n) { return pos['n:' + n.uuid] && n.connected && n.users > 0; }).sort(byY(pos));
    // нода → выход: у каждого internet-выхода свои порты по числу входящих линий
    var sinkEdges = [];
    ordered.forEach(function (sk) {
      if (sk.kind !== 'internet') return;
      var sp = pos['s:' + sk.tag];
      var src = active.filter(function (n) { return (n.sinks || []).indexOf(sk.tag) >= 0; });
      src.forEach(function (n, i) {
        var p = pos['n:' + n.uuid];
        sinkEdges.push({ n: n, d: [p.x + nodeW, p.y, sp.x, port(sp.y, NH, i, src.length)] });
      });
    });

    srcEdges.forEach(function (se) {
      var n = se.n, c = se.c, e = se.d;
      var w = widthFor(cUsers(n, c), maxClassUsers).toFixed(2);
      var lv = n.connected && cMbps(n, c) > 0, cls = (lv ? 'live ' : 'idle ') + c.cls;
      s += '<path class="lf-flow ' + cls + '" stroke-width="' + w + '"' + (lv ? phase() : '') + ' d="' + edge(e[0], e[1], e[2], e[3]) + '"/>';
    });
    sinkEdges.forEach(function (se) {
      var w = widthFor(se.n.users, maxUsers).toFixed(2), e = se.d;
      var lv = isLive(se.n), cls = lv ? 'live' : 'idle';
      s += '<path class="lf-flow ' + cls + '" stroke-width="' + w + '"' + (lv ? phase() : '') + ' d="' + edge(e[0], e[1], e[2], e[3]) + '"/>';
    });
    // каскад: источник (колонка 2) → цель (колонка 3), янтарная линия в саму ноду
    nodes.forEach(function (n) {
      var p = pos['n:' + n.uuid];
      if (!p) return;
      (n.cascades || []).forEach(function (tu) {
        var tp = pos['n:' + tu];
        if (!tp) return;
        var lv = isLive(n);
        s += '<path class="lf-casc' + (lv ? ' live' : '') + '"' + (lv ? phase() : '') + ' d="' + edge(p.x + nodeW, p.y, tp.x, tp.y) + '"/>';
      });
    });
    // Бейдж с числом — на своей линии, у входа в ноду (к этому месту линии уже
    // разошлись на шаг карточек и кружки не налезают ни друг на друга, ни на
    // чужие линии).
    // Бейдж-«пилюля»: счётчик ноды · реально активных по панели (второе число
    // акцентным цветом). Без данных об активных — просто кружок со счётчиком.
    // Карточки-источники слева (группы по типу сети или одна «Пользователи»)
    classes.forEach(function (c) {
      var cy = c.y;
      var tip = c.title + ' · ' + c.users + t().active + (c.mbps != null ? ' · ' + t().vpn + c.mbps.toFixed(2) + t().mbps : '');
      var gsel = selected === 'g:' + c.k ? ' sel' : '';
      s += '<g class="lf-node lf-grp" data-group="' + c.k + '" role="button" tabindex="0"><title>' + esc(tip) + '</title>';
      s += '<rect class="lf-box lf-src-' + c.cls + gsel + '" x="' + userX + '" y="' + (cy - userH / 2) + '" width="' + userW + '" height="' + userH + '" rx="8"/>';
      s += ico(c.icon, userX + 14, cy - 9);
      s += '<text class="lf-t" x="' + (userX + TXT) + '" y="' + (cy - 10) + '" dominant-baseline="central">' + esc(c.title) + '</text>';
      var sub = c.users + t().active + (c.mbps != null ? ' · ' + c.mbps.toFixed(2) + t().mbps : '');
      s += '<text class="lf-s" x="' + (userX + TXT) + '" y="' + (cy + 12) + '" dominant-baseline="central">' + esc(sub) + '</text></g>';
    });
    // Карточки нод: текст слева от иконки, а не по центру — длинные имена
    // иначе наезжали на иконку. Карточка кликабельна (data-uuid) — открывает
    // список пользователей на ноде.
    nodes.forEach(function (n) {
      var p = pos['n:' + n.uuid];
      if (!p) return;
      var y = p.y - NH / 2, off = (n.connected && n.users) ? '' : ' off';
      var sel = selected === 'n:' + n.uuid ? ' sel' : '';
      var tip = n.name + (n.active != null ? ' · ' + t().activeTip + ': ' + n.active : '')
        + (n.vpn_split ? ' · ' + splitText(n.vpn_split) : '')
        + (n.connected ? ' · ' + t().net + ': ↑ ' + n.tx_mbps.toFixed(2) + ' ↓ ' + n.rx_mbps.toFixed(2) + t().mbps : '')
        + (n.profile ? ' · ' + t().profile + ': ' + n.profile : '')
        + ((n.inbounds || []).length ? ' · ' + t().inbounds + ': ' + n.inbounds.join(', ') : '');
      s += '<g class="lf-node" data-uuid="' + esc(n.uuid) + '" role="button" tabindex="0"><title>' + esc(tip) + '</title>';
      s += '<rect class="lf-box' + off + sel + '" x="' + p.x + '" y="' + y + '" width="' + nodeW + '" height="' + NH + '" rx="8"/>';
      s += ico('node', p.x + 16, y + 19);
      s += '<text class="lf-t" x="' + (p.x + TXT) + '" y="' + (y + 21) + '" dominant-baseline="central">' + esc(n.name) + '</text>';
      var sub = !n.connected ? t().offline
        : n.users ? (n.vpn_mbps != null ? (t().vpn + n.vpn_mbps.toFixed(2) + t().mbps) : ('↑ ' + n.tx_mbps.toFixed(2) + ' · ↓ ' + n.rx_mbps.toFixed(2) + t().mbps)) : t().noUsers;
      s += '<text class="lf-s" x="' + (p.x + TXT) + '" y="' + (y + 39) + '" dominant-baseline="central">' + esc(sub) + '</text>';
      // Онлайн — в карточке, справа: реально активных по панели (акцент) · счётчик ноды
      if (n.connected && (n.users > 0 || (n.active != null && n.active > 0))) {
        s += '<text class="lf-cnt" x="' + (p.x + nodeW - 12) + '" y="' + (y + 39) + '" text-anchor="end" dominant-baseline="central">'
          + (n.active != null ? '<tspan class="lf-cnt-a">' + n.active + '</tspan><tspan class="lf-cnt-d"> · </tspan>' : '') + n.users + '</text>';
      }
      s += '</g>';
    });
    ordered.forEach(function (sk) {
      var p = pos['s:' + sk.tag], y = p.y - NH / 2, off = sk.kind === 'internet' ? '' : ' off';
      s += '<rect class="lf-box' + off + '" x="' + p.x + '" y="' + y + '" width="' + sinkW + '" height="' + NH + '" rx="8"/>';
      s += ico(sk.kind, p.x + 16, y + 19);
      s += '<text class="lf-t" x="' + (p.x + TXT) + '" y="' + (y + 21) + '" dominant-baseline="central">' + esc(sinkTitle(sk, live.length > 1)) + '</text>';
      s += '<text class="lf-s" x="' + (p.x + TXT) + '" y="' + (y + 39) + '" dominant-baseline="central">' + (sk.kind === 'internet' ? t().toNet : t().noMeasure) + '</text>';
    });
    return s + '</svg>';
  }

  function ensureStyle() {
    if (document.getElementById('lf-style')) return;
    var st = document.createElement('style');
    st.id = 'lf-style';
    var V = '#' + VIEW_ID + ' ';
    st.textContent =
      V + '.lf-h1{font:500 30px/1.2 ui-sans-serif,system-ui,sans-serif;color:hsl(var(--foreground, 220 9% 84%));margin:0 0 4px}' +
      V + '.lf-sub{color:hsl(var(--muted-foreground, 220 9% 56%));font:400 14px/1.4 ui-sans-serif,system-ui,sans-serif;margin:0 0 22px}' +
      V + '.lf-card{background:hsl(var(--card, 220 20% 10%));border:1px solid hsl(var(--border, 220 14% 18%));border-radius:14px;padding:16px 18px 12px}' +
      V + '.lf-head{display:flex;align-items:baseline;gap:14px;margin-bottom:10px;font:500 15px/1.2 ui-sans-serif,system-ui,sans-serif;color:hsl(var(--foreground, 220 9% 84%))}' +
      V + '.lf-total{color:hsl(var(--primary, 239 84% 67%));font-size:13px}' +
      V + '.lf-meta{margin-left:auto;color:hsl(var(--muted-foreground, 220 9% 56%));font-size:12px;font-weight:400}' +
      // Схема подстраивается под окно: по ширине — viewBox, по высоте — max-height
      // от fit() (доступная высота окна минус легенда и панель), xMidYMin meet.
      V + '.lf-body{display:flex;flex-direction:column;gap:12px}' +
      V + '.lf-canvas{flex:1 1 auto;min-width:0;text-align:center;position:relative;overflow:hidden;touch-action:none}' +
      V + '.lf-zoom{transform-origin:0 0;will-change:transform}' +
      V + '.lf-zoomed .lf-canvas{cursor:grab}' + V + '.lf-canvas.lf-dragging{cursor:grabbing}' +
      V + '.lf-zoomctl{position:absolute;top:6px;right:8px;display:flex;gap:4px;z-index:2}' +
      V + '.lf-zb{background:hsl(var(--card, 220 20% 10%) / .9);color:hsl(var(--foreground, 220 9% 84%));border:1px solid hsl(var(--border, 220 14% 18%));border-radius:6px;min-width:26px;height:24px;padding:0 7px;font:500 12px/1 ui-sans-serif,system-ui,sans-serif;cursor:pointer}' +
      V + '.lf-zb:hover{border-color:hsl(var(--primary, 239 84% 67%) / .6)}' +
      V + '.lf-zv{min-width:46px;font-variant-numeric:tabular-nums}' +
      V + '.lf-canvas svg{display:block;width:100%;height:auto;max-height:70vh;margin:0 auto}' +
      // На широком окне панель «кто на ноде» встаёт справа и не отъедает высоту у схемы
      '@media (min-width:1100px){' + V + '.lf-body{flex-direction:row;align-items:flex-start}' + V + '.lf-panel.open{flex:0 0 clamp(420px, 46%, 700px)}' + V + '.lf-pw{max-height:60vh}}' +
      V + '.lf-legend{display:flex;gap:18px;flex-wrap:wrap;color:hsl(var(--muted-foreground, 220 9% 56%));font:400 12px/1 ui-sans-serif,system-ui,sans-serif;margin-top:14px}' +
      V + '.lf-legend i{display:inline-block;width:24px;height:0;border-top:2px dashed currentColor;vertical-align:middle;margin-right:6px}' +
      V + '.lf-cap{fill:hsl(var(--muted-foreground, 220 9% 56%));font:400 11px/1 sans-serif;letter-spacing:.08em}' +
      V + '.lf-ico{fill:none;stroke:hsl(var(--muted-foreground, 220 9% 56%));stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}' +
      V + '.lf-t{fill:hsl(var(--foreground, 220 9% 84%));font:500 14px/1 sans-serif}' +
      V + '.lf-s{fill:hsl(var(--muted-foreground, 220 9% 56%));font:400 12px/1 sans-serif}' +
      V + '.lf-box{fill:hsl(var(--muted, 220 14% 16%));stroke:hsl(var(--border, 220 14% 18%));stroke-width:1}' +
      V + '.lf-box.off{opacity:.45}' +
      V + '.lf-node{cursor:pointer;outline:none}' +
      V + '.lf-noclick .lf-node{cursor:default}' +
      V + '.lf-noclick .lf-node:hover .lf-box{stroke:hsl(var(--border, 220 14% 18%))}' +
      V + '.lf-node:hover .lf-box,' + V + '.lf-node:focus .lf-box{stroke:hsl(var(--primary, 239 84% 67%) / .7)}' +
      V + '.lf-box.sel{stroke:hsl(var(--primary, 239 84% 67%));stroke-width:1.6;fill:hsl(var(--primary, 239 84% 67%) / .12)}' +
      V + '.lf-flow{fill:none;stroke-linecap:round;stroke-dasharray:7 6;pointer-events:none}' +
      V + '.lf-flow.live{stroke:hsl(var(--primary, 239 84% 67%) / .8);animation:lf-dash ' + DASH_MS + 'ms linear infinite}' +
      V + '.lf-flow.live.f{stroke:hsl(270 70% 66% / .85)}' +
      V + '.lf-flow.live.u{stroke:hsl(var(--muted-foreground, 220 9% 56%) / .7)}' +
      V + '.lf-box.lf-src-f{stroke:hsl(270 70% 66% / .55)}' +
      V + '.lf-box.lf-src-m{stroke:hsl(var(--primary, 239 84% 67%) / .55)}' +
      V + '.lf-flow.idle{stroke:hsl(var(--muted-foreground, 220 9% 56%) / .3)}' +
      V + '.lf-casc{fill:none;stroke-linecap:round;stroke-dasharray:2 5;stroke-width:1.8;stroke:hsl(38 80% 55% / .65);pointer-events:none}' +
      V + '.lf-casc.live{stroke:hsl(38 90% 60% / .9);animation:lf-dash ' + DASH_MS + 'ms linear infinite}' +
      V + '.lf-badge{fill:hsl(var(--card, 220 20% 10%));stroke:hsl(var(--primary, 239 84% 67%) / .5);stroke-width:1;pointer-events:none}' +
      V + '.lf-badge-t{fill:hsl(var(--foreground, 220 9% 84%));font:500 12px/1 sans-serif;pointer-events:none}' +
      V + '.lf-badge-d{fill:hsl(var(--muted-foreground, 220 9% 56%))}' +
      V + '.lf-cnt{fill:hsl(var(--foreground, 220 9% 84%));font:500 12.5px/1 sans-serif;pointer-events:none}' +
      V + '.lf-cnt-a{fill:hsl(var(--primary, 239 84% 67%));font-weight:600}' +
      V + '.lf-cnt-d{fill:hsl(var(--muted-foreground, 220 9% 56%))}' +
      V + '.lf-legend b.lf-sw{display:inline-block;width:18px;height:0;border-top:2px dashed;vertical-align:middle;margin:0 4px 0 8px}' +
      V + '.lf-badge-a{fill:hsl(var(--primary, 239 84% 67%));font-weight:600}' +
      // Панель «кто на ноде»
      V + '.lf-panel{display:none;min-width:0;border:1px solid hsl(var(--border, 220 14% 18%));border-radius:10px;background:hsl(var(--muted, 220 14% 16%) / .5);padding:10px 14px 6px;font:400 13px/1.4 ui-sans-serif,system-ui,sans-serif;color:hsl(var(--foreground, 220 9% 84%))}' +
      V + '.lf-panel.open{display:block}' +
      V + '.lf-ph{display:flex;align-items:baseline;gap:12px;flex-wrap:nowrap;margin-bottom:6px;min-width:0}' +
      V + '.lf-ph b{font-weight:500;font-size:14px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
      V + '.lf-ph .lf-pc{color:hsl(var(--muted-foreground, 220 9% 56%));font-size:12px;white-space:nowrap;flex:0 0 auto}' +
      V + '.lf-ph .lf-px{margin-left:auto;flex:0 0 auto;white-space:nowrap;background:none;border:1px solid hsl(var(--border, 220 14% 18%));color:inherit;border-radius:6px;padding:2px 9px;font:inherit;font-size:12px;cursor:pointer}' +
      V + '.lf-ph .lf-px:hover{border-color:hsl(var(--primary, 239 84% 67%) / .6)}' +
      V + '.lf-pn{color:hsl(var(--muted-foreground, 220 9% 56%));font-size:12px;margin:4px 0 6px}' +
      V + '.lf-pw{overflow:auto;max-height:38vh}' +
      // Сетка колонок фиксированная: IPv6 (39 символов) иначе распирал колонку IP и
      // сжимал AS до одного слова в строке.
      V + '.lf-tbl{width:100%;border-collapse:collapse;font-size:12.5px;table-layout:fixed}' +
      V + '.lf-tbl th{text-align:left;font-weight:500;color:hsl(var(--muted-foreground, 220 9% 56%));font-size:11px;letter-spacing:.06em;text-transform:uppercase;padding:4px 10px 6px 0;border-bottom:1px solid hsl(var(--border, 220 14% 18%));white-space:nowrap;overflow:hidden;text-overflow:ellipsis}' +
      V + '.lf-tbl td{padding:5px 10px 5px 0;border-bottom:1px solid hsl(var(--border, 220 14% 18%) / .6);vertical-align:top;overflow-wrap:anywhere}' +
      V + '.lf-tbl td.lf-u{overflow-wrap:normal;word-break:break-word}' +
      V + '.lf-tbl td.lf-as b{font-weight:500;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}' +
      V + '.lf-tbl td.lf-as span.lf-asn,' + V + '.lf-tbl td.lf-as span.lf-geo{display:block;color:hsl(var(--muted-foreground, 220 9% 56%));font-size:12px}' +
      V + '.lf-tbl td.lf-as span.lf-geo{font-size:11.5px;opacity:.85}' +
      V + '.lf-tbl .lf-ip6 .lf-dim{font-size:11.5px}' +
      V + '.lf-tbl tr:last-child td{border-bottom:0}' +
      V + '.lf-tbl .lf-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}' +
      V + '.lf-tbl td.lf-ip4{white-space:nowrap}' +
      V + '.lf-tbl .lf-dim{color:hsl(var(--muted-foreground, 220 9% 56%))}' +
      V + '.lf-tag{display:inline-block;border:1px solid hsl(var(--border, 220 14% 18%));border-radius:99px;padding:0 7px;font-size:10.5px;margin-left:6px;color:hsl(var(--muted-foreground, 220 9% 56%))}' +
      '@keyframes lf-dash{to{stroke-dashoffset:-26}}' +
      '@media (prefers-reduced-motion: reduce){' + V + '.lf-flow.live,' + V + '.lf-casc.live{animation:none}}';
    document.head.appendChild(st);
  }

  var lastData = null, curLang = lang(), selected = null, panelData = null, canViewUsers = true;
  // Масштаб схемы: трансформ живёт на обёртке .lf-zoom, поэтому переживает перерисовку SVG каждые 5 с
  var zoom = { k: 1, x: 0, y: 0 }, ZMIN = 0.5, ZMAX = 4;

  // Подгонка масштаба под окно: ширина — сама (viewBox), высоту ограничиваем
  // тем, что осталось от окна ниже схемы (легенда, панель, поля). Иначе при
  // 10+ нодах схема уезжала за нижний край и требовала прокрутки.
  function fit(view) {
    var svg = view.querySelector('.lf-canvas svg');
    if (!svg) return;
    var top = view.querySelector('.lf-canvas').getBoundingClientRect().top;
    var legend = view.querySelector('.lf-legend'), panel = view.querySelector('.lf-panel');
    var below = panel && panel.classList.contains('open') && panel.getBoundingClientRect().top >= top + 40;
    var reserve = (legend ? legend.offsetHeight : 0) + (below ? panel.offsetHeight + 12 : 0) + 36;
    var avail = window.innerHeight - top - reserve;
    svg.style.maxHeight = Math.max(240, Math.floor(avail)) + 'px';
  }

  function paint(view, d) {
    view.querySelector('.lf-zoom').innerHTML = renderSvg(d, selected);
    canViewUsers = d.can_view_users !== false;   // false — права view_users нет; клики не предлагаем
    view.classList.toggle('lf-noclick', !canViewUsers);
    view.querySelector('.lf-h1').textContent = t().title;
    view.querySelector('.lf-sub').textContent = canViewUsers ? t().sub : t().subNoUsers;
    view.querySelector('.lf-now').textContent = t().now;
    view.querySelector('.lf-total').textContent = (d.total_active != null ? d.total_active + t().active + ' · ' : '') + (d.total_users || 0) + t().online + ' · ' + (d.nodes || []).length + t().nodesCnt;
    var asOf = d.active_as_of ? new Date(d.active_as_of) : null;
    view.querySelector('.lf-meta').textContent = t().updated + new Date().toLocaleTimeString(locale())
      + (asOf && !isNaN(asOf.getTime()) ? ' · ' + t().asOf + asOf.toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit' }) : '')
      + (d.live_source ? ' · ' + (d.live_source === 'panel-live' ? t().liveSrc : t().dbSrc) : '')
      + (d.poll_error === 'panel_timeout' ? t().pollTimeout : d.poll_error ? t().pollErr : '')
      + (d.poll_truncated ? ' · ' + t().pTrunc : '');
    var other = (d.sinks || []).filter(function (s) { return s.kind !== 'internet'; });
    view.querySelector('.lf-note').textContent = d.profiles_available === false
      ? t().noProfiles
      : other.length ? t().noteA + other.map(function (sk) { return sinkTitle(sk, false); }).join(', ') + t().noteB : '';
    var lg = view.querySelectorAll('.lf-legend span');
    if (lg.length >= 3) {
      lg[0].innerHTML = '<i style="color:hsl(var(--primary, 239 84% 67%))"></i>' + t().lgLive;
      lg[1].innerHTML = '<i style="color:hsl(var(--muted-foreground, 220 9% 56%))"></i>' + t().lgIdle;
      lg[2].textContent = t().lgBadge;
    }
    var sl = view.querySelector('.lf-split-lg');
    if (sl) sl.innerHTML = d.vpn_split_total
      ? t().lgSplit + '<b class="lf-sw" style="border-color:hsl(var(--primary, 239 84% 67%))"></b>' + t().mob + ' <b class="lf-sw" style="border-color:hsl(270 70% 66%)"></b>' + t().fix + ' <b class="lf-sw" style="border-color:hsl(var(--muted-foreground, 220 9% 56%))"></b>' + t().unk
      : '';
    if (panelData) paintPanel(view, panelData);
    fit(view);
  }

  function fmtSince(iso) {
    if (!iso) return '';
    var dt = new Date(iso);
    if (isNaN(dt.getTime())) return '';
    var sameDay = dt.toDateString() === new Date().toDateString();
    return sameDay ? dt.toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit' })
      : dt.toLocaleString(locale(), { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  }

  // IPv6 показываем как префикс /64 + хвост: первые четыре группы — это и есть
  // «абонент» (у мобильных операторов /64 на устройство), interface-id — шум.
  // Перенос разрешён ровно после префикса, чтобы адрес не рвался где попало.
  function fmtIp(ip) {
    ip = String(ip || '');
    if (ip.indexOf(':') < 0) return '<span class="lf-mono">' + esc(ip) + '</span>';
    var groups = ip.split(':'), cut = 0;
    // конец 4-й группы; '::' (пустая группа = схлопнутые нули) режет префикс раньше
    for (var i = 0; i < groups.length && cut < 4; i++) {
      if (groups[i] === '') break;
      cut = i + 1;
    }
    var head = groups.slice(0, cut).join(':') + ':', tail = groups.slice(cut).join(':');
    if (!cut || !tail) return '<span class="lf-mono lf-ip6">' + esc(ip) + '</span>';
    return '<span class="lf-mono lf-ip6">' + esc(head) + '<wbr><span class="lf-dim">' + esc(tail) + '</span></span>';
  }

  function paintPanel(view, pd) {
    var panel = view.querySelector('.lf-panel');
    var tt = t();
    var isGrp = !!pd.group;
    var h = '<div class="lf-ph"><b>' + (isGrp ? groupTitle(pd.group) : tt.pUsers + ': ' + esc(pd.node.name)) + '</b>';
    h += '<span class="lf-pc">' + (isGrp
      ? tt.pGroup + pd.count + (pd.vpn_mbps != null ? ' · ' + tt.vpn + pd.vpn_mbps.toFixed(2) + tt.mbps : '')
      : tt.pSeen + pd.count + tt.pOf + pd.node.users_online + tt.pByPanel) + '</span>';
    h += '<button type="button" class="lf-px" aria-label="' + tt.pClose + '">✕ ' + tt.pClose + '</button></div>';
    if (!pd.users.length) {
      var mins = Math.max(1, Math.round((pd.window_s || 180) / 60));
      h += '<div class="lf-pn">' + (pd.unavailable ? tt.pNoLive : (!isGrp && pd.node.users_online > 0 ? tt.pEmptyA + mins + tt.pEmptyB : tt.pNone)) + '</div>';
    } else {
      h += isGrp
        ? '<div class="lf-pw"><table class="lf-tbl"><colgroup><col style="width:20%"><col style="width:28%"><col style="width:26%"><col style="width:14%"><col style="width:12%"></colgroup>'
        : '<div class="lf-pw"><table class="lf-tbl"><colgroup><col style="width:24%"><col style="width:32%"><col style="width:30%"><col style="width:14%"></colgroup>';
      h += '<thead><tr><th>' + tt.thUser + '</th><th>' + tt.thIp + '</th><th>' + tt.thAs + ' · ' + tt.thGeo + '</th>' + (isGrp ? '<th>' + tt.thNode + '</th>' : '') + '<th>' + tt.thSince + '</th></tr></thead><tbody>';
      // Один пользователь — одна ячейка (rowspan), под ним все его IP: иначе
      // юзер с двумя адресами читался как два человека.
      var groups = [], byKey = {};
      pd.users.forEach(function (u) {
        var k = String(u.user) + '|' + String(u.telegram_id || '');
        if (!byKey[k]) { byKey[k] = { u: u, rows: [] }; groups.push(byKey[k]); }
        byKey[k].rows.push(u);
      });
      groups.forEach(function (g) {
        var u = g.u;
        var who = esc(u.user) + (u.telegram_id && String(u.telegram_id) !== String(u.user).replace(/^user_|^rs_/, '') ? ' <span class="lf-dim">· tg ' + esc(u.telegram_id) + '</span>' : '');
        if (u.tag) who += '<span class="lf-tag">' + esc(u.tag) + '</span>';
        g.rows.forEach(function (r, i) {
          var as = r.asn ? '<b>AS' + esc(r.asn) + '</b>' : '<span class="lf-dim">—</span>';
          if (r.mobile) as += '<span class="lf-tag">' + tt.mobile + '</span>';
          if (r.hosting) as += '<span class="lf-tag">' + tt.hosting + '</span>';
          if (r.as_name) as += '<span class="lf-asn">' + esc(r.as_name) + '</span>';
          if (r.country || r.city) as += '<span class="lf-geo">' + esc([r.country, r.city].filter(Boolean).join(' · ')) + '</span>';
          var since = esc(fmtSince(r.since))
            + (i === 0 && r.vpn_mbps != null ? '<span style="display:block">' + t().vpn + r.vpn_mbps.toFixed(2) + t().mbps + '</span>' : '')
            + (r.inbound ? '<span class="lf-dim" style="display:block">' + esc(r.inbound) + '</span>' : '');
          var ipCls = String(r.ip || '').indexOf(':') >= 0 ? 'lf-ip6c' : 'lf-ip4';
          var ipCell = r.ip ? fmtIp(r.ip) : '<span class="lf-dim">—</span>';
          var nodeCell = isGrp ? '<td class="lf-dim">' + esc(r.node || '—') + '</td>' : '';
          h += '<tr>' + (i === 0 ? '<td class="lf-u" rowspan="' + g.rows.length + '">' + who + '</td>' : '')
            + '<td class="' + ipCls + '">' + ipCell + '</td><td class="lf-as">' + as + '</td>' + nodeCell + '<td class="lf-dim">' + since + '</td></tr>';
        });
      });
      h += '</tbody></table></div>';
    }
    // Список пересобирается каждые 5 с — позицию прокрутки сохраняем, иначе
    // её сбрасывало наверх на каждом обновлении.
    var pw0 = panel.querySelector('.lf-pw'), st = pw0 ? pw0.scrollTop : 0;
    panel.innerHTML = h;
    panel.classList.add('open');
    var pw1 = panel.querySelector('.lf-pw');
    if (pw1 && st) pw1.scrollTop = st;
    panel.querySelector('.lf-px').addEventListener('click', function () { closePanel(view); });
  }

  function panelUrl(key) {
    return key.indexOf('g:') === 0
      ? API_BASE + '/group/' + encodeURIComponent(key.slice(2)) + '/users'
      : API_BASE + '/node/' + encodeURIComponent(key.slice(2)) + '/users';
  }
  function groupTitle(k) { return k === 'mobile' ? t().mobBox : k === 'fixed' ? t().fixBox : k === 'unknown' ? t().unkBox : t().allBox; }
  function loadPanel(view, uuid) {
    return fetch(panelUrl(uuid), { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (pd) {
        if (selected !== uuid) return;   // успели переключить/закрыть
        panelData = pd;
        paintPanel(view, pd);
        fit(view);
      })
      .catch(function (e) {
        if (selected !== uuid) return;
        var panel = view.querySelector('.lf-panel');
        panel.innerHTML = '<div class="lf-ph"><b>' + t().pUsers + '</b><span class="lf-pc">' + t().pErr + esc(e.message) + '</span><button type="button" class="lf-px">✕ ' + t().pClose + '</button></div>';
        panel.classList.add('open');
        panel.querySelector('.lf-px').addEventListener('click', function () { closePanel(view); });
        fit(view);
      });
  }

  function openPanel(view, uuid) {
    if (selected === uuid) { closePanel(view); return; }
    selected = uuid;
    panelData = null;
    if (lastData) view.querySelector('.lf-zoom').innerHTML = renderSvg(lastData, selected);
    var panel = view.querySelector('.lf-panel');
    panel.innerHTML = '<div class="lf-ph"><b>' + t().pUsers + '</b><span class="lf-pc">' + t().loading + '</span></div>';
    panel.classList.add('open');
    loadPanel(view, uuid);
    if (panelTimer) clearInterval(panelTimer);
    panelTimer = setInterval(function () { if (selected) loadPanel(view, selected); }, REFRESH_MS);
    fit(view);
  }

  function closePanel(view) {
    selected = null;
    panelData = null;
    if (panelTimer) { clearInterval(panelTimer); panelTimer = null; }
    var panel = view.querySelector('.lf-panel');
    panel.classList.remove('open');
    panel.innerHTML = '';
    if (lastData) view.querySelector('.lf-zoom').innerHTML = renderSvg(lastData, null);
    fit(view);
  }

  function tick(view) {
    return fetch(DATA_URL, { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) { lastData = d; paint(view, d); })
      .catch(function (e) { view.querySelector('.lf-meta').textContent = t().nodata + e.message; });
  }

  function build() {
    var view = document.createElement('div');
    view.id = VIEW_ID;
    view.innerHTML =
      '<h1 class="lf-h1">' + t().title + '</h1>' +
      '<p class="lf-sub">' + t().sub + '</p>' +
      '<div class="lf-card">' +
      '<div class="lf-head"><span class="lf-now">' + t().now + '</span><span class="lf-total">—</span><span class="lf-meta">' + t().loading + '</span></div>' +
      '<div class="lf-body"><div class="lf-canvas"><div class="lf-zoom"></div>' +
      '<div class="lf-zoomctl" title="' + t().zHint + '"><button type="button" class="lf-zb" data-z="out" title="' + t().zOut + '">−</button>' +
      '<button type="button" class="lf-zb lf-zv" data-z="reset" title="' + t().zReset + '">100%</button>' +
      '<button type="button" class="lf-zb" data-z="in" title="' + t().zIn + '">+</button></div></div><div class="lf-panel"></div></div>' +
      '<div class="lf-legend"><span><i style="color:hsl(var(--primary, 239 84% 67%))"></i>' + t().lgLive + '</span>' +
      '<span><i style="color:hsl(var(--muted-foreground, 220 9% 56%))"></i>' + t().lgIdle + '</span>' +
      '<span>' + t().lgBadge + '</span><span class="lf-split-lg"></span><span class="lf-note"></span></div></div>';
    // Клик/Enter по карточке ноды — делегирование на холст (SVG пересобирается
    // каждые 5 с, вешать обработчики на сами карточки бессмысленно).
    var canvas = view.querySelector('.lf-canvas');
    function pick(ev) {
      var g = ev.target && ev.target.closest ? ev.target.closest('.lf-node') : null;
      if (!g || !canViewUsers) return;
      ev.preventDefault();
      var grp = g.getAttribute('data-group');
      openPanel(view, grp ? 'g:' + grp : 'n:' + g.getAttribute('data-uuid'));
    }
    canvas.addEventListener('click', function (ev) { if (dragged) { dragged = false; return; } pick(ev); });
    canvas.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') pick(ev); });
    setupZoom(view, canvas);
    return view;
  }

  // ── масштаб: кнопки, колесо (к курсору), перетаскивание ──
  var dragged = false;
  function applyZoom(view) {
    var z = view.querySelector('.lf-zoom'), v = view.querySelector('.lf-zv');
    if (z) z.style.transform = 'translate(' + zoom.x.toFixed(1) + 'px,' + zoom.y.toFixed(1) + 'px) scale(' + zoom.k.toFixed(3) + ')';
    if (v) v.textContent = Math.round(zoom.k * 100) + '%';
    view.classList.toggle('lf-zoomed', zoom.k !== 1 || zoom.x !== 0 || zoom.y !== 0);
  }
  function zoomAt(view, factor, cx, cy) {
    // cx, cy — точка в координатах .lf-canvas, которая должна остаться на месте
    var k2 = Math.min(ZMAX, Math.max(ZMIN, zoom.k * factor));
    if (k2 === zoom.k) return;
    zoom.x = cx - (cx - zoom.x) * (k2 / zoom.k);
    zoom.y = cy - (cy - zoom.y) * (k2 / zoom.k);
    zoom.k = k2;
    if (Math.abs(zoom.k - 1) < 0.01) { zoom.k = 1; }
    applyZoom(view);
  }
  function resetZoom(view) { zoom.k = 1; zoom.x = 0; zoom.y = 0; applyZoom(view); }
  function setupZoom(view, canvas) {
    var ctl = view.querySelector('.lf-zoomctl');
    ctl.addEventListener('click', function (ev) {
      var b = ev.target && ev.target.closest ? ev.target.closest('.lf-zb') : null;
      if (!b) return;
      ev.preventDefault(); ev.stopPropagation();
      var r = canvas.getBoundingClientRect(), cx = r.width / 2, cy = r.height / 2;
      if (b.getAttribute('data-z') === 'in') zoomAt(view, 1.25, cx, cy);
      else if (b.getAttribute('data-z') === 'out') zoomAt(view, 1 / 1.25, cx, cy);
      else resetZoom(view);
    });
    // Колесо: масштаб к курсору; preventDefault, чтобы страница не листалась под схемой
    canvas.addEventListener('wheel', function (ev) {
      if (ev.target && ev.target.closest && ev.target.closest('.lf-zoomctl')) return;
      ev.preventDefault();
      var r = canvas.getBoundingClientRect();
      var f = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
      zoomAt(view, f, ev.clientX - r.left, ev.clientY - r.top);
    }, { passive: false });
    // Перетаскивание: двигаем схему; от клика отличаем по сдвигу > 4px
    var down = null;
    canvas.addEventListener('pointerdown', function (ev) {
      if (ev.button !== 0 || (ev.target && ev.target.closest && ev.target.closest('.lf-zoomctl'))) return;
      down = { x: ev.clientX, y: ev.clientY, zx: zoom.x, zy: zoom.y, moved: false, id: ev.pointerId };
    });
    canvas.addEventListener('pointermove', function (ev) {
      if (!down || ev.pointerId !== down.id) return;
      var dx = ev.clientX - down.x, dy = ev.clientY - down.y;
      if (!down.moved && Math.abs(dx) + Math.abs(dy) < 4) return;
      if (!down.moved) { down.moved = true; canvas.classList.add('lf-dragging'); try { canvas.setPointerCapture(ev.pointerId); } catch (e) { /* ignore */ } }
      zoom.x = down.zx + dx; zoom.y = down.zy + dy;
      applyZoom(view);
    });
    function up(ev) {
      if (!down) return;
      if (down.moved) { dragged = true; setTimeout(function () { dragged = false; }, 0); }
      canvas.classList.remove('lf-dragging');
      try { canvas.releasePointerCapture(down.id); } catch (e) { /* ignore */ }
      down = null;
    }
    canvas.addEventListener('pointerup', up);
    canvas.addEventListener('pointercancel', up);
    // Двойной клик по пустому месту — сброс
    canvas.addEventListener('dblclick', function (ev) {
      if (ev.target && ev.target.closest && (ev.target.closest('.lf-node') || ev.target.closest('.lf-zoomctl'))) return;
      resetZoom(view);
    });
    applyZoom(view);
  }

  function mount(el) {
    unmount();
    ensureStyle();
    var view = build();
    el.appendChild(view);
    tick(view);
    timer = setInterval(function () { tick(view); }, REFRESH_MS);
    langTimer = setInterval(function () {
      var l = lang();
      if (l === curLang) return;
      curLang = l;
      if (lastData) paint(view, lastData);
    }, 700);
    resizeFn = function () { fit(view); };
    window.addEventListener('resize', resizeFn);
    keyFn = function (ev) { if (ev.key === 'Escape' && selected) closePanel(view); };
    document.addEventListener('keydown', keyFn);
  }

  function unmount() {
    if (timer) { clearInterval(timer); timer = null; }
    if (langTimer) { clearInterval(langTimer); langTimer = null; }
    if (panelTimer) { clearInterval(panelTimer); panelTimer = null; }
    if (resizeFn) { window.removeEventListener('resize', resizeFn); resizeFn = null; }
    if (keyFn) { document.removeEventListener('keydown', keyFn); keyFn = null; }
    selected = null; panelData = null; zoom = { k: 1, x: 0, y: 0 };
    var v = document.getElementById(VIEW_ID);
    if (v) v.remove();
  }

  window.rwaPluginUI = window.rwaPluginUI || {};
  window.rwaPluginUI[PLUGIN_ID] = { mount: mount, unmount: unmount };
})();
"""
