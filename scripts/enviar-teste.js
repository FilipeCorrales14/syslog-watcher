#!/usr/bin/env node
// Envia mensagens syslog de exemplo para testar o coletor localmente.
//   node scripts/enviar-teste.js [host] [porta]

import dgram from 'node:dgram';

const host = process.argv[2] ?? '127.0.0.1';
const port = Number(process.argv[3] ?? 5514);

const now = new Date();
const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const bsdDate = `${months[now.getMonth()]} ${String(now.getDate()).padStart(2, ' ')} ${now.toTimeString().slice(0, 8)}`;

const messages = [
  `<38>${bsdDate} srv-web sshd[812]: Accepted publickey for deploy from 10.0.0.5 port 50122`,
  ...Array.from({ length: 6 }, (_, i) =>
    `<38>${bsdDate} srv-web sshd[9${i}1]: Failed password for root from 203.0.113.7 port 4${i}210 ssh2`),
  '<187>45: *Mar  1 00:01:23.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down',
  `<165>1 ${now.toISOString()} fw-borda filterlog - - - bloqueado: TCP 198.51.100.4:445 -> 192.168.1.10:445`,
  `<130>${bsdDate} nobreak-01 upsd[55]: Bateria em nível crítico, desligamento em 5 minutos`,
];

const socket = dgram.createSocket('udp4');
let sent = 0;
for (const message of messages) {
  socket.send(message, port, host, () => {
    if (++sent === messages.length) {
      console.log(`${sent} mensagens enviadas para ${host}:${port}`);
      socket.close();
    }
  });
}
