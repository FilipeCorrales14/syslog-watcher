import dgram from 'node:dgram';
import { parse } from './parse.js';

// Recebe syslog via UDP, grava e passa pelas regras.
// O tratamento de cada datagrama é síncrono (SQLite é síncrono), o que
// mantém a ordem de chegada e dispensa fila.

export function createCollector({ store, engine, onAlert = () => {}, now = () => new Date() }) {
  const socket = dgram.createSocket('udp4');
  const stats = { received: 0, failed: 0 };

  function handle(raw, sourceIp) {
    const at = now();
    const log = parse(raw, { sourceIp, now: at });
    store.saveLog(log, { receivedAt: at.toISOString(), sourceIp });
    for (const alert of engine.evaluate(log, at.getTime())) {
      store.saveAlert(alert, at.toISOString());
      onAlert(alert);
    }
  }

  socket.on('message', (raw, rinfo) => {
    stats.received++;
    try {
      handle(raw, rinfo.address);
    } catch (err) {
      stats.failed++;
      console.error(`falha ao processar mensagem de ${rinfo.address}: ${err.message}`);
    }
  });

  return {
    socket,
    stats,
    handle,
    listen(port, host = '0.0.0.0') {
      return new Promise((resolve, reject) => {
        socket.once('error', reject);
        socket.bind(port, host, () => {
          socket.off('error', reject);
          resolve(socket.address());
        });
      });
    },
    close() {
      return new Promise((resolve) => socket.close(resolve));
    },
  };
}
