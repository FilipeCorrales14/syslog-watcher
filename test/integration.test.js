import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { Store } from '../src/store.js';
import { RuleEngine } from '../src/rules.js';
import { createCollector } from '../src/collector.js';
import { createApi } from '../src/api.js';

let collector;
let api;
let base;
let udpPort;
const alerts = [];

before(async () => {
  const store = new Store();
  const engine = new RuleEngine([
    { name: 'ssh', pattern: 'Failed password', threshold: { count: 3, windowS: 60 } },
  ]);
  collector = createCollector({ store, engine, onAlert: (a) => alerts.push(a) });
  udpPort = (await collector.listen(0, '127.0.0.1')).port;
  api = createApi({ store, collector });
  await new Promise((r) => api.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${api.address().port}`;
});

after(async () => {
  await collector.close();
  api.close();
});

function send(messages) {
  const socket = dgram.createSocket('udp4');
  return Promise.all(
    messages.map((m) => new Promise((r) => socket.send(m, udpPort, '127.0.0.1', r))),
  ).then(() => socket.close());
}

async function waitFor(condition) {
  for (let i = 0; i < 50; i++) {
    if (condition()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('tempo esgotado esperando condição');
}

test('recebe via UDP, grava, alerta e expõe na API', async () => {
  await send([
    '<38>Oct 30 14:00:01 srv-web sshd[1]: Failed password for root from 203.0.113.7',
    '<38>Oct 30 14:00:02 srv-web sshd[2]: Failed password for root from 203.0.113.7',
    '<38>Oct 30 14:00:03 srv-web sshd[3]: Failed password for admin from 203.0.113.7',
    '<187>45: *Mar  1 00:01:23.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down',
    '<14>Oct 30 14:00:04 nas01 smbd[9]: 100% de uso no volume',
  ]);
  await waitFor(() => collector.stats.received === 5);

  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].host, 'srv-web');

  const all = await (await fetch(`${base}/logs`)).json();
  assert.equal(all.length, 5);

  const errors = await (await fetch(`${base}/logs?severity=err`)).json();
  assert.deepEqual(errors.map((l) => l.app), ['LINK']);
  assert.equal(errors[0].host, '127.0.0.1');

  const byHost = await (await fetch(`${base}/logs?host=srv-web&q=admin`)).json();
  assert.equal(byHost.length, 1);

  // "%" no texto de busca é literal, não curinga do LIKE
  const literal = await (await fetch(`${base}/logs?q=${encodeURIComponent('100%')}`)).json();
  assert.equal(literal.length, 1);

  const stored = await (await fetch(`${base}/alerts`)).json();
  assert.equal(stored[0].rule, 'ssh');

  const stats = await (await fetch(`${base}/stats`)).json();
  assert.equal(stats.collector.received, 5);
  assert.equal(stats.topHosts[0].host, 'srv-web');
});

test('parâmetros inválidos', async () => {
  assert.equal((await fetch(`${base}/logs?severity=9`)).status, 400);
  assert.equal((await fetch(`${base}/logs?severity=urgente`)).status, 400);
  assert.equal((await fetch(`${base}/nada`)).status, 404);
  assert.equal((await fetch(`${base}/logs`, { method: 'POST' })).status, 405);
});
