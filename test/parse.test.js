import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse } from '../src/parse.js';

const now = new Date('2026-10-30T15:00:00');

test('RFC 3164', () => {
  const log = parse('<38>Oct 30 14:02:11 srv-web sshd[812]: Failed password for root', { sourceIp: '10.0.0.2', now });
  assert.equal(log.facility, 4); // auth
  assert.equal(log.severity, 6);
  assert.equal(log.severityName, 'info');
  assert.equal(log.host, 'srv-web');
  assert.equal(log.app, 'sshd');
  assert.equal(log.message, 'Failed password for root');
  assert.equal(new Date(log.timestamp).getFullYear(), 2026);
});

test('RFC 3164 com dia de um dígito e sem PID', () => {
  const log = parse('<13>Nov  3 08:00:00 nas01 cron: job ok', { now: new Date('2026-11-03T09:00:00') });
  assert.equal(log.app, 'cron');
  assert.equal(log.message, 'job ok');
});

test('RFC 3164 de dezembro recebida em janeiro fica no ano anterior', () => {
  const log = parse('<13>Dec 31 23:59:00 h app: x', { now: new Date('2027-01-01T00:01:00') });
  assert.equal(new Date(log.timestamp).getFullYear(), 2026);
});

test('RFC 5424 com structured data e BOM', () => {
  const raw = '<165>1 2026-10-30T14:02:11.003Z fw-borda filterlog 4021 ID47 [origin ip="10.0.0.1"] ﻿bloqueado: TCP';
  const log = parse(raw, { sourceIp: '10.0.0.1' });
  assert.equal(log.facility, 20); // local4
  assert.equal(log.severity, 5);
  assert.equal(log.host, 'fw-borda');
  assert.equal(log.app, 'filterlog');
  assert.equal(log.message, 'bloqueado: TCP');
  assert.equal(log.timestamp, '2026-10-30T14:02:11.003Z');
});

test('RFC 5424 com campos nulos usa o IP de origem', () => {
  const log = parse('<14>1 - - - - - - mensagem simples', { sourceIp: '192.168.1.9', now });
  assert.equal(log.host, '192.168.1.9');
  assert.equal(log.app, null);
  assert.equal(log.message, 'mensagem simples');
});

test('formato Cisco IOS: host vem do IP e app do código %FAC-SEV-MNEM', () => {
  const raw = '<187>45: *Mar  1 00:01:23.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down';
  const log = parse(raw, { sourceIp: '10.0.0.254', now });
  assert.equal(log.severity, 3);
  assert.equal(log.facility, 23);
  assert.equal(log.host, '10.0.0.254');
  assert.equal(log.app, 'LINK');
  assert.match(log.message, /changed state to down/);
});

test('mensagem sem PRI é aceita como notice', () => {
  const log = parse('texto solto', { sourceIp: '10.1.1.1', now });
  assert.equal(log.severity, 5);
  assert.equal(log.message, 'texto solto');
  assert.equal(log.host, '10.1.1.1');
});

test('PRI fora do intervalo é tratado como sem cabeçalho', () => {
  const log = parse('<999>x', { sourceIp: 'h', now });
  assert.equal(log.message, '<999>x');
});
