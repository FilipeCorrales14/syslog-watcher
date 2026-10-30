// Motor de regras de alerta.
//
// Uma regra combina filtros (severidade máxima, host, aplicação, regex na
// mensagem) com um limiar: "N ocorrências em X segundos". Depois de
// disparar, a regra fica em silêncio pelo tempo de cooldown, para que uma
// interface oscilando não gere cem alertas em um minuto.
//
// A contagem é separada por host: 5 falhas de login no firewall e 1 no
// servidor não somam 6.

export function compileRule(rule) {
  if (!rule.name) throw new Error('regra sem "name"');
  const count = rule.threshold?.count ?? 1;
  const windowS = rule.threshold?.windowS ?? 60;
  if (!Number.isInteger(count) || count < 1) throw new Error(`${rule.name}: threshold.count inválido`);

  return {
    name: rule.name,
    maxSeverity: rule.maxSeverity ?? 7,
    host: rule.host ? new RegExp(rule.host, 'i') : null,
    app: rule.app ? new RegExp(rule.app, 'i') : null,
    pattern: rule.pattern ? new RegExp(rule.pattern, 'i') : null,
    count,
    windowMs: windowS * 1000,
    cooldownMs: (rule.cooldownS ?? 300) * 1000,
  };
}

export function matches(rule, log) {
  if (log.severity > rule.maxSeverity) return false;
  if (rule.host && !rule.host.test(log.host ?? '')) return false;
  if (rule.app && !rule.app.test(log.app ?? '')) return false;
  if (rule.pattern && !rule.pattern.test(log.message)) return false;
  return true;
}

export class RuleEngine {
  constructor(rules) {
    this.rules = rules.map(compileRule);
    this.hits = new Map(); // "regra|host" -> timestamps recentes
    this.silencedUntil = new Map();
  }

  evaluate(log, nowMs = Date.now()) {
    const alerts = [];

    for (const rule of this.rules) {
      if (!matches(rule, log)) continue;

      const key = `${rule.name}|${log.host}`;
      const recent = (this.hits.get(key) ?? []).filter((t) => nowMs - t < rule.windowMs);
      recent.push(nowMs);
      this.hits.set(key, recent);

      if (recent.length < rule.count) continue;
      if ((this.silencedUntil.get(key) ?? 0) > nowMs) continue;

      this.silencedUntil.set(key, nowMs + rule.cooldownMs);
      this.hits.set(key, []);
      alerts.push({
        rule: rule.name,
        host: log.host,
        count: recent.length,
        windowS: rule.windowMs / 1000,
        lastMessage: log.message,
      });
    }

    return alerts;
  }
}
