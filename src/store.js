import { DatabaseSync } from 'node:sqlite';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS logs (
  id          INTEGER PRIMARY KEY,
  received_at TEXT    NOT NULL,
  source_ip   TEXT,
  timestamp   TEXT    NOT NULL,
  host        TEXT,
  app         TEXT,
  facility    INTEGER NOT NULL,
  severity    INTEGER NOT NULL,
  message     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_received ON logs (received_at);
CREATE INDEX IF NOT EXISTS idx_logs_host_sev ON logs (host, severity);

CREATE TABLE IF NOT EXISTS alerts (
  id           INTEGER PRIMARY KEY,
  created_at   TEXT    NOT NULL,
  rule         TEXT    NOT NULL,
  host         TEXT,
  count        INTEGER NOT NULL,
  last_message TEXT    NOT NULL
);
`;

export class Store {
  constructor(path = ':memory:') {
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec(SCHEMA);
    this.insertLog = this.db.prepare(`
      INSERT INTO logs (received_at, source_ip, timestamp, host, app, facility, severity, message)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    this.insertAlert = this.db.prepare(`
      INSERT INTO alerts (created_at, rule, host, count, last_message) VALUES (?, ?, ?, ?, ?)`);
  }

  saveLog(log, { receivedAt, sourceIp }) {
    this.insertLog.run(receivedAt, sourceIp, log.timestamp, log.host, log.app, log.facility, log.severity, log.message);
  }

  saveAlert(alert, createdAt) {
    this.insertAlert.run(createdAt, alert.rule, alert.host, alert.count, alert.lastMessage);
  }

  // Filtros vêm da query string; nada é concatenado direto no SQL.
  searchLogs({ maxSeverity, host, app, text, since, limit = 100 } = {}) {
    const where = [];
    const params = [];
    if (maxSeverity !== undefined) {
      where.push('severity <= ?');
      params.push(maxSeverity);
    }
    if (host) {
      where.push('host = ?');
      params.push(host);
    }
    if (app) {
      where.push('app = ?');
      params.push(app);
    }
    if (text) {
      where.push("message LIKE ? ESCAPE '\\'");
      params.push(`%${text.replace(/[\\%_]/g, '\\$&')}%`);
    }
    if (since) {
      where.push('received_at >= ?');
      params.push(since);
    }
    const sql = `
      SELECT * FROM logs
      ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY id DESC
      LIMIT ?`;
    return this.db.prepare(sql).all(...params, limit);
  }

  stats(since) {
    return {
      bySeverity: this.db
        .prepare('SELECT severity, COUNT(*) AS total FROM logs WHERE received_at >= ? GROUP BY severity ORDER BY severity')
        .all(since),
      topHosts: this.db
        .prepare(`
          SELECT host, COUNT(*) AS total,
                 SUM(CASE WHEN severity <= 3 THEN 1 ELSE 0 END) AS errors
            FROM logs WHERE received_at >= ?
           GROUP BY host ORDER BY total DESC LIMIT 10`)
        .all(since),
    };
  }

  recentAlerts(limit = 50) {
    return this.db.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT ?').all(limit);
  }

  prune(beforeIso) {
    return this.db.prepare('DELETE FROM logs WHERE received_at < ?').run(beforeIso).changes;
  }
}
