// Заголовок группы CDN зависит от режима: метки владельца в конфиге («Через CDN»)
// или угадывание по настройкам инбаунда («Предположительно CDN»).
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadModule, makeData } from './harness.mjs';

function cdnTitles(lang, mode) {
  const { renderSvg } = loadModule({ lang });
  const d = makeData(2);
  d.cdn_mode = mode;
  return [...renderSvg(d, null).matchAll(/<title>([^<]*)<\/title>/g)].map((m) => m[1]).filter((x) => x.includes('CDN ·'));
}

test('метки в конфиге — «Через CDN», без меток — «Предположительно CDN»', () => {
  assert.ok(cdnTitles('ru', 'declared')[0].startsWith('Через CDN'));
  assert.ok(cdnTitles('ru', 'heuristic')[0].startsWith('Предположительно CDN'));
  assert.ok(cdnTitles('en', 'declared')[0].startsWith('Via CDN'));
  assert.ok(cdnTitles('en', 'heuristic')[0].startsWith('Presumably CDN'));
  // старый ответ /data без поля cdn_mode ведёт себя как угадывание
  assert.ok(cdnTitles('ru', undefined)[0].startsWith('Предположительно CDN'));
});
