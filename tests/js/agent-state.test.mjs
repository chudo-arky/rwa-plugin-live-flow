// Состояние агента ноды доезжает в подсказку карточки — и на обоих языках,
// потому что t().key читается без фолбэка: пропущенный ключ даёт «undefined».
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadModule, makeData } from './harness.mjs';

function tips(lang, state) {
  const { renderSvg } = loadModule({ lang });
  const d = makeData(2);
  d.nodes[0].agent_state = state;
  d.nodes[1].agent_state = 'log';
  const svg = renderSvg(d, null);
  return [...svg.matchAll(/<title>([^<]*)<\/title>/g)].map((m) => m[1]);
}

for (const lang of ['ru', 'en']) {
  test('подсказка про агента: ' + lang, () => {
    for (const state of ['none', 'metrics_only']) {
      const t = tips(lang, state).filter((s) => s.startsWith('node-1'));
      assert.equal(t.length, 1);
      assert.ok(t[0].length > tips(lang, 'log').filter((s) => s.startsWith('node-1'))[0].length, state);
      assert.ok(!t[0].includes('undefined'), state + ' / ' + lang);
    }
    // у рабочей ноды подсказка чистая
    assert.ok(!tips(lang, 'log').some((s) => s.includes('undefined')));
  });
}
