// Регрессия: в режиме «столбец» при 1–3 нодах и четырёх группах карточки групп
// наезжали друг на друга (каждая отдельно прижималась к верху) и вылезали за
// нижний край холста. Проверяем координаты, отсутствие перекрытий и обрезания
// в обеих раскладках, с фильтрацией большого парка и с ручной расстановкой.
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadModule, parseSvg, overlaps, makeData } from './harness.mjs';

function check(svg, label) {
  const { W, H, rects } = parseSvg(svg);
  assert.ok(rects.length > 0, label + ': карточки не найдены');
  for (const r of rects) {
    assert.ok(r.x >= 0 && r.y >= 0, label + ': карточка левее/выше холста ' + JSON.stringify(r));
    assert.ok(r.x + r.w <= W + 0.01, label + ': карточка правее холста ' + JSON.stringify(r) + ' W=' + W);
    assert.ok(r.y + r.h <= H + 0.01, label + ': карточка ниже холста ' + JSON.stringify(r) + ' H=' + H);
  }
  const groups = rects.filter((r) => /lf-src-/.test(r.cls));
  for (let i = 0; i < groups.length; i++)
    for (let j = i + 1; j < groups.length; j++)
      assert.ok(!overlaps(groups[i], groups[j]), label + ': группы перекрываются ' + JSON.stringify([groups[i], groups[j]]));
  // интервалы между группами сохранены (одинаковый шаг сверху вниз)
  const ys = groups.map((g) => g.y).sort((a, b) => a - b);
  for (let i = 1; i < ys.length; i++) assert.ok(ys[i] - ys[i - 1] >= groups[0].h, label + ': шаг групп меньше высоты карточки');
  return { W, H, rects, groups };
}

for (const n of [1, 2, 3, 12]) {
  test('столбец: ' + n + ' нод(ы), четыре группы — без перекрытий и обрезания', () => {
    const I = loadModule();
    I.prefs.view = 'column'; I.prefs.q = ''; I.prefs.pos = {}; I.prefs.posGrid = {};
    const { groups, H } = check(I.renderSvg(makeData(n), null), 'column/' + n);
    assert.equal(groups.length, 4);
    assert.ok(groups[groups.length - 1].y + groups[groups.length - 1].h + 20 <= H, 'нижний край группы учтён в высоте');
  });
}

test('столбец: две ноды — раньше mobile и fixed получали один y=34', () => {
  const I = loadModule();
  I.prefs.view = 'column'; I.prefs.q = ''; I.prefs.pos = {};
  const { groups } = check(I.renderSvg(makeData(2), null), 'column/2');
  const ys = groups.map((g) => g.y);
  assert.equal(new Set(ys).size, 4, 'у всех групп разный y: ' + ys.join(','));
});

test('столбец: большой парк, отфильтрованный до 1–3 нод', () => {
  const I = loadModule();
  I.prefs.view = 'column'; I.prefs.pos = {};
  for (const q of ['node-7', 'node-1']) {   // node-1 матчит node-1, node-10..19 → несколько нод
    I.prefs.q = q;
    check(I.renderSvg(makeData(60), null), 'column/filter ' + q);
  }
});

test('столбец: каскады и прыжки не ломают геометрию групп', () => {
  const I = loadModule();
  I.prefs.view = 'column'; I.prefs.q = ''; I.prefs.pos = {};
  const { rects } = check(I.renderSvg(makeData(5, { cascades: true }), null), 'column/cascade');
  assert.equal(rects.filter((r) => /lf-hopbox/.test(r.cls)).length, 3);
});

test('колонки: 1, 2, 3 и большой парк — без перекрытий и обрезания', () => {
  const I = loadModule();
  I.prefs.view = 'grid'; I.prefs.q = ''; I.prefs.posGrid = {};
  for (const n of [1, 2, 3, 45]) check(I.renderSvg(makeData(n, { cascades: n > 3 }), null), 'grid/' + n);
});

test('ручная расстановка расширяет холст под сдвинутую карточку', () => {
  const I = loadModule();
  I.prefs.view = 'column'; I.prefs.q = '';
  const d = makeData(3);
  I.prefs.pos = { ['n:' + d.nodes[0].uuid]: { dx: 900, dy: 700 } };
  const { rects, W, H } = check(I.renderSvg(d, null), 'column/pos');
  const moved = rects.find((r) => r.x > 1200);
  assert.ok(moved && moved.x + moved.w <= W && moved.y + moved.h <= H);
  I.prefs.pos = {};
});
