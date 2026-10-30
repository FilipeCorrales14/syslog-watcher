import { readFileSync } from 'node:fs';
import { Store } from './store.js';
import { RuleEngine } from './rules.js';
import { createCollector } from './collector.js';
import { createApi } from './api.js';

const SYSLOG_PORT = Number(process.env.SYSLOG_PORT ?? 5514);
const HTTP_PORT = Number(process.env.HTTP_PORT ?? 3000);
const DB_PATH = process.env.DB_PATH ?? 'syslog.db';
const RULES_FILE = process.env.RULES_FILE ?? 'config/rules.example.json';
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS ?? 14);
const WEBHOOK_URL = process.env.WEBHOOK_URL;

const store = new Store(DB_PATH);
const rules = JSON.parse(readFileSync(RULES_FILE, 'utf8'));
const engine = new RuleEngine(rules);

async function notify(alert) {
  const freq = alert.count > 1 ? ` (${alert.count}x em ${alert.windowS}s)` : '';
  const text = `[${alert.rule}] ${alert.host}${freq}: ${alert.lastMessage}`;
  console.log(`ALERTA ${text}`);
  if (!WEBHOOK_URL) return;
  try {
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text, ...alert }),
      signal: AbortSignal.timeout(5000),
    });
  } catch (err) {
    console.error(`falha no webhook: ${err.message}`);
  }
}

const collector = createCollector({ store, engine, onAlert: notify });
const { port } = await collector.listen(SYSLOG_PORT);
console.log(`Recebendo syslog em UDP ${port} com ${engine.rules.length} regra(s)`);

const api = createApi({ store, collector });
api.listen(HTTP_PORT, () => console.log(`API em http://localhost:${HTTP_PORT}`));

setInterval(() => {
  const removed = store.prune(new Date(Date.now() - RETENTION_DAYS * 86_400_000).toISOString());
  if (removed) console.log(`${removed} log(s) antigo(s) removido(s)`);
}, 3_600_000).unref();

process.on('SIGTERM', async () => {
  await collector.close();
  api.close(() => process.exit(0));
});
