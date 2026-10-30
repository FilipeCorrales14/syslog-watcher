import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RuleEngine, compileRule, matches } from '../src/rules.js';

const log = (over = {}) => ({ host: 'srv', app: 'sshd', severity: 6, message: 'Failed password for root', ...over });

test('filtros de severidade, host, app e padrão', () => {
  const rule = compileRule({ name: 'r', maxSeverity: 4, host: '^fw-', app: 'filter', pattern: 'bloqueado' });
  assert.equal(matches(rule, log({ host: 'fw-1', app: 'filterlog', severity: 4, message: 'bloqueado' })), true);
  assert.equal(matches(rule, log({ host: 'fw-1', app: 'filterlog', severity: 5, message: 'bloqueado' })), false);
  assert.equal(matches(rule, log({ host: 'sw-1', app: 'filterlog', severity: 4, message: 'bloqueado' })), false);
  assert.equal(matches(rule, log({ host: 'fw-1', app: 'filterlog', severity: 4, message: 'liberado' })), false);
});

test('dispara ao atingir o limiar dentro da janela', () => {
  const engine = new RuleEngine([{ name: 'ssh', pattern: 'Failed', threshold: { count: 3, windowS: 60 } }]);
  assert.deepEqual(engine.evaluate(log(), 0), []);
  assert.deepEqual(engine.evaluate(log(), 10_000), []);
  const [alert] = engine.evaluate(log(), 20_000);
  assert.equal(alert.rule, 'ssh');
  assert.equal(alert.count, 3);
});

test('ocorrências fora da janela não contam', () => {
  const engine = new RuleEngine([{ name: 'ssh', pattern: 'Failed', threshold: { count: 3, windowS: 60 } }]);
  engine.evaluate(log(), 0);
  engine.evaluate(log(), 30_000);
  assert.deepEqual(engine.evaluate(log(), 61_000), []); // a de t=0 já saiu
  assert.equal(engine.evaluate(log(), 62_000).length, 1);
});

test('cooldown evita repetição e a contagem recomeça depois', () => {
  const engine = new RuleEngine([{ name: 'down', pattern: 'down', cooldownS: 120 }]);
  const m = log({ message: 'link down' });
  assert.equal(engine.evaluate(m, 0).length, 1);
  assert.equal(engine.evaluate(m, 60_000).length, 0);
  assert.equal(engine.evaluate(m, 121_000).length, 1);
});

test('contagem é separada por host', () => {
  const engine = new RuleEngine([{ name: 'ssh', pattern: 'Failed', threshold: { count: 2, windowS: 60 } }]);
  engine.evaluate(log({ host: 'a' }), 0);
  assert.equal(engine.evaluate(log({ host: 'b' }), 1000).length, 0);
  assert.equal(engine.evaluate(log({ host: 'a' }), 2000).length, 1);
});

test('várias regras podem disparar para o mesmo log', () => {
  const engine = new RuleEngine([
    { name: 'critico', maxSeverity: 2 },
    { name: 'nobreak', pattern: 'bateria' },
  ]);
  const alerts = engine.evaluate(log({ severity: 2, message: 'Bateria em nível crítico' }), 0);
  assert.deepEqual(alerts.map((a) => a.rule), ['critico', 'nobreak']);
});

test('regra inválida é rejeitada', () => {
  assert.throws(() => compileRule({}), /name/);
  assert.throws(() => compileRule({ name: 'x', threshold: { count: 0 } }), /count/);
  assert.throws(() => compileRule({ name: 'x', pattern: '(' }));
});
