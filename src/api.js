import http from 'node:http';
import { SEVERITIES } from './parse.js';

export function createApi({ store, collector, now = () => new Date() }) {
  return http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    try {
      if (req.method !== 'GET') return send(res, 405, { error: 'apenas GET' });

      if (url.pathname === '/logs') {
        const q = url.searchParams;
        return send(res, 200, store.searchLogs({
          maxSeverity: severityParam(q.get('severity')),
          host: q.get('host') || undefined,
          app: q.get('app') || undefined,
          text: q.get('q') || undefined,
          since: q.get('since') || undefined,
          limit: Math.min(Number(q.get('limit') ?? 100) || 100, 1000),
        }).map(withSeverityName));
      }

      if (url.pathname === '/stats') {
        const since = new Date(now().getTime() - 86_400_000).toISOString();
        const { bySeverity, topHosts } = store.stats(since);
        return send(res, 200, {
          since,
          collector: collector?.stats ?? null,
          bySeverity: bySeverity.map((r) => ({ ...r, name: SEVERITIES[r.severity] })),
          topHosts,
        });
      }

      if (url.pathname === '/alerts') return send(res, 200, store.recentAlerts());
      if (url.pathname === '/health') return send(res, 200, { status: 'ok' });

      return send(res, 404, { error: 'rota não encontrada' });
    } catch (err) {
      if (err.status) return send(res, err.status, { error: err.message });
      console.error(err);
      return send(res, 500, { error: 'erro interno' });
    }
  });
}

// Aceita número (0-7) ou nome ("err", "warning"): ?severity=err traz err e mais graves.
function severityParam(value) {
  if (value === null || value === '') return undefined;
  const byName = SEVERITIES.indexOf(value.toLowerCase());
  const n = byName >= 0 ? byName : Number(value);
  if (!Number.isInteger(n) || n < 0 || n > 7) {
    throw Object.assign(new Error(`severity inválida. Use 0-7 ou ${SEVERITIES.join(', ')}`), { status: 400 });
  }
  return n;
}

function withSeverityName(row) {
  return { ...row, severity_name: SEVERITIES[row.severity] };
}

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(payload);
}
