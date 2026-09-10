// Загружает MODULE_JS из rwa_live_flow/module.py в песочницу без DOM и отдаёт
// внутренности рендера (renderSvg/renderGrid/prefs). Геометрия проверяется по
// строке SVG: карточки — <rect class="lf-box …" x y width height>, холст — data-w/data-h.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, '..', '..', 'rwa_live_flow', 'module.py'), 'utf8');
const m = src.match(/MODULE_JS = r"""([\s\S]*?)"""/);
if (!m) throw new Error('MODULE_JS not found');

export function loadModule({ lang = 'ru' } = {}) {
  const store = new Map();
  const sandbox = {
    document: { currentScript: null },
    localStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) },
    navigator: { language: lang },
    console,
    setInterval: () => 0, clearInterval: () => {}, setTimeout: () => 0, clearTimeout: () => {},
    requestAnimationFrame: (f) => f(),
    Date, Math, JSON, String, Number, Array, Object, RegExp, parseFloat, parseInt, isNaN, encodeURIComponent, decodeURIComponent,
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(m[1], sandbox, { filename: 'module.js' });
  return sandbox.window.rwaPluginUI.live_flow.__internals;
}

// Разбор карточек из SVG-строки: класс rect, координаты, а также data-w/data-h.
export function parseSvg(svg) {
  const head = svg.match(/<svg [^>]*data-w="([\d.]+)" data-h="([\d.]+)"/);
  const rects = [];
  const re = /<rect class="lf-box([^"]*)" x="([\d.-]+)" y="([\d.-]+)" width="([\d.-]+)" height="([\d.-]+)"/g;
  let r;
  while ((r = re.exec(svg))) rects.push({ cls: r[1].trim(), x: +r[2], y: +r[3], w: +r[4], h: +r[5] });
  return { W: +head[1], H: +head[2], rects };
}

export function overlaps(a, b) {
  return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
}

// Обезличенный парк: n нод, все четыре группы непустые, у первой ноды каскады на остальные.
export function makeData(n, { cascades = false, fourGroups = true } = {}) {
  const uuids = Array.from({ length: n }, (_, i) => '00000000-0000-4000-8000-' + String(i).padStart(12, '0'));
  const nodes = uuids.map((uuid, i) => ({
    uuid, name: 'node-' + (i + 1), position: i, users: 3 + (i % 4), tx_mbps: 1, rx_mbps: 1, vpn_mbps: 0.5,
    vpn_split: { mobile: 0.2, fixed: 0.2, cdn: 0.1, unknown: 0.1, mobile_users: 1, fixed_users: 1, cdn_users: 1, unknown_users: 1 },
    connected: true, active: 1, profile: 'p', inbounds: ['in'], sinks: ['DIRECT'],
    cascades: cascades && i === 0 ? uuids.slice(1, 4) : [],
  }));
  return {
    total_users: 10, total_active: 5, live_source: 'panel-live', active_window_s: 180,
    vpn_split_total: fourGroups
      ? { mobile: 1, fixed: 1, cdn: 1, unknown: 1, mobile_users: 2, fixed_users: 2, cdn_users: 1, unknown_users: 1, unknown_why: { no_conn: 1 } }
      : { mobile: 1, fixed: 1, cdn: 0, unknown: 0, mobile_users: 2, fixed_users: 2, cdn_users: 0, unknown_users: 0 },
    profiles_available: true, profiles_stale: false, snippets_unresolved: [], can_view_users: true,
    nodes, sinks: [{ tag: 'DIRECT', title: 'Интернет', kind: 'internet' }, { tag: 'BLOCK', title: 'Блокировка', kind: 'block' }],
  };
}
