// Parser de mensagens syslog.
//
// Equipamentos de rede raramente seguem uma RFC à risca, então a ordem é:
//   1. RFC 5424:  <PRI>1 2026-10-30T14:02:11Z host app 123 ID - mensagem
//   2. RFC 3164:  <PRI>Oct 30 14:02:11 host app[123]: mensagem
//   3. Qualquer outra coisa com <PRI>: guarda a mensagem como veio e usa o
//      IP de origem como host. Cobre o formato padrão de switches Cisco:
//      <187>45: *Mar  1 00:01:23.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down

export const SEVERITIES = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

const RFC5424 = /^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\](?:\[.*?\])*) ?(.*)$/s;
const RFC3164 = /^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ([^:\[\s]+)(?:\[(\d+)\])?: ?(.*)$/s;
const CISCO_TAG = /%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+)/;

export function parse(raw, { sourceIp, now = new Date() } = {}) {
  const text = raw.toString('utf8').replace(/\s+$/, '');
  const pri = /^<(\d{1,3})>/.exec(text);

  if (!pri || Number(pri[1]) > 191) {
    return build({ facility: 1, severity: 5, host: sourceIp, app: null, message: text, timestamp: now });
  }

  const value = Number(pri[1]);
  const base = { facility: value >> 3, severity: value & 7 };
  const rest = text.slice(pri[0].length);

  const m5424 = RFC5424.exec(rest);
  if (m5424) {
    const [, ts, host, app, , , , message] = m5424;
    return build({
      ...base,
      timestamp: ts === '-' ? now : new Date(ts),
      host: nil(host) ?? sourceIp,
      app: nil(app),
      message: message.replace(/^﻿/, ''),
    });
  }

  const m3164 = RFC3164.exec(rest);
  if (m3164) {
    const [, mon, day, hh, mm, ss, host, app, , message] = m3164;
    return build({
      ...base,
      timestamp: inferYear(MONTHS.indexOf(mon), Number(day), Number(hh), Number(mm), Number(ss), now),
      host,
      app,
      message,
    });
  }

  const cisco = CISCO_TAG.exec(rest);
  return build({
    ...base,
    timestamp: now,
    host: sourceIp,
    app: cisco ? cisco[1] : null,
    message: rest.trim(),
  });
}

function build(fields) {
  const timestamp = Number.isNaN(fields.timestamp?.getTime?.()) ? new Date() : fields.timestamp;
  return { ...fields, timestamp: timestamp.toISOString(), severityName: SEVERITIES[fields.severity] };
}

function nil(value) {
  return value === '-' ? null : value;
}

// RFC 3164 não tem ano. Usa o ano atual, a não ser que a data fique no
// futuro: aí é uma mensagem de dezembro chegando em janeiro.
function inferYear(month, day, hh, mm, ss, now) {
  const candidate = new Date(now.getFullYear(), month, day, hh, mm, ss);
  if (candidate.getTime() - now.getTime() > 86_400_000) {
    candidate.setFullYear(now.getFullYear() - 1);
  }
  return candidate;
}
