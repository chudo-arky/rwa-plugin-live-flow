// Легенда и подписи выходов: сбои опроса IP и метрик видны всегда, а английский
// интерфейс не получает русских названий, пришедших с сервера.
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadModule, makeData } from './harness.mjs';

test('сбои IP и метрик видны и при недоступных профилях', () => {
  const { configNotes } = loadModule({ lang: 'ru' });
  const d = makeData(2);
  d.profiles_available = false;
  d.conn_error = 'connections_unavailable';
  d.metrics_error = 'metrics_unavailable';
  const notes = configNotes(d);
  assert.equal(notes.length, 3);
  assert.ok(notes.some((n) => n.includes('опрос IP у панели')));
});

test('без сбоев и выходов без цифр легенда пустая', () => {
  const { configNotes } = loadModule({ lang: 'en' });
  const d = makeData(2);
  d.sinks = d.sinks.filter((s) => s.kind === 'internet');
  assert.deepEqual([...configNotes(d)], []);
});

test('DIRECT в английском интерфейсе — Internet, даже среди нескольких internet-выходов', () => {
  const { sinkTitle } = loadModule({ lang: 'en' });
  const direct = { tag: 'DIRECT', title: 'Интернет', kind: 'internet' };
  assert.equal(sinkTitle(direct, true), 'Internet');
  assert.equal(sinkTitle(direct, false), 'Internet');
  assert.equal(sinkTitle({ tag: 'BLOCK', title: 'Блокировка', kind: 'block' }, true), 'Blocked');
  // прочие internet-выходы различаются по тегу
  assert.equal(sinkTitle({ tag: 'direct-v6', title: 'direct-v6', kind: 'internet' }, true), 'direct-v6');
});

test('в русском интерфейсе названия прежние', () => {
  const { sinkTitle } = loadModule({ lang: 'ru' });
  assert.equal(sinkTitle({ tag: 'DIRECT', title: 'Интернет', kind: 'internet' }, true), 'Интернет');
});
