# Syslog Watcher

Coletor de syslog para redes pequenas e médias. Recebe as mensagens de switches, firewalls, servidores e nobreaks via UDP, guarda em SQLite, permite buscar pela API e dispara alertas quando uma regra é atendida, como "5 falhas de login SSH em 1 minuto" ou "interface caiu".

Para quem precisa de logs centralizados e alertas básicos, mas não tem estrutura para manter um Graylog ou uma pilha ELK.

## Como rodar

Node.js 22.13 ou superior, sem dependências.

```bash
npm start
```

Em outro terminal, envie mensagens de exemplo:

```bash
npm run enviar-teste
```

```
Recebendo syslog em UDP 5514 com 4 regra(s)
API em http://localhost:3000
ALERTA [Tentativas de login SSH falhando] srv-web (5x em 60s): Failed password for root from 203.0.113.7 port 44210 ssh2
ALERTA [Interface de rede caiu] 127.0.0.1: 45: *Mar  1 00:01:23.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
ALERTA [Erro crítico em qualquer equipamento] nobreak-01: Bateria em nível crítico, desligamento em 5 minutos
```

A porta padrão é 5514 porque a 514 exige root. Para receber na 514 sem rodar o Node como root, redirecione no firewall do servidor:

```bash
sudo iptables -t nat -A PREROUTING -p udp --dport 514 -j REDIRECT --to-port 5514
```

Configuração por variáveis de ambiente: `SYSLOG_PORT`, `HTTP_PORT`, `DB_PATH`, `RULES_FILE`, `RETENTION_DAYS` (padrão 14) e `WEBHOOK_URL`.

## Formatos aceitos

Equipamentos de rede raramente seguem a RFC à risca. O parser (`src/parse.js`) tenta, nesta ordem:

| Formato         | Exemplo                                                                    |
| --------------- | -------------------------------------------------------------------------- |
| RFC 5424        | `<165>1 2026-10-30T14:02:11Z fw-borda filterlog 4021 - - bloqueado: TCP`   |
| RFC 3164 (BSD)  | `<38>Oct 30 14:02:11 srv-web sshd[812]: Failed password for root`         |
| Cisco IOS       | `<187>45: *Mar  1 00:01:23: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down` |
| Sem cabeçalho   | qualquer texto, gravado como `notice` com o IP de origem como host        |

Detalhes tratados: severidade e facility extraídas do PRI, ano inferido nas mensagens BSD (que não trazem ano, então uma mensagem de 31/12 recebida em 01/01 fica no ano certo), BOM do RFC 5424, campos nulos (`-`) e o código `%FACILIDADE-SEVERIDADE-MNEMÔNICO` do Cisco usado como nome da aplicação.

## Regras de alerta

Ficam em um arquivo JSON (`config/rules.example.json`):

```json
{
  "name": "Tentativas de login SSH falhando",
  "pattern": "Failed password|authentication failure",
  "threshold": { "count": 5, "windowS": 60 },
  "cooldownS": 600
}
```

| Campo         | Descrição                                                        |
| ------------- | ---------------------------------------------------------------- |
| `pattern`     | regex aplicada na mensagem (sem diferenciar maiúsculas)          |
| `maxSeverity` | 0 (emerg) a 7 (debug); casa com essa severidade e as mais graves |
| `host`, `app` | regex sobre o host e a aplicação                                 |
| `threshold`   | quantas ocorrências em quantos segundos; padrão 1 em 60          |
| `cooldownS`   | silêncio depois de disparar; padrão 300                          |

A contagem é feita por host: 3 falhas no firewall e 2 no servidor não somam 5. O cooldown evita que uma interface oscilando gere um alerta a cada mensagem.

## API

```bash
curl 'localhost:3000/logs?severity=err'              # err e mais graves (aceita 0-7 ou nome)
curl 'localhost:3000/logs?host=srv-web&q=Failed'     # host exato + texto na mensagem
curl 'localhost:3000/logs?since=2026-10-30T00:00:00Z&limit=500'
curl  localhost:3000/alerts                          # alertas disparados
curl  localhost:3000/stats                           # últimas 24h por severidade e por host
```

## Decisões

- **Processamento síncrono por datagrama.** O SQLite do Node é síncrono, então cada mensagem é gravada e avaliada na ordem de chegada, sem fila. Para o volume de uma rede de algumas dezenas de equipamentos isso sobra; acima disso, o próximo passo seria agrupar inserções em transações.
- **Busca segura.** Os filtros da API viram parâmetros do SQL, nunca texto concatenado. Até o `%` digitado na busca é escapado para não virar curinga do `LIKE`.
- **Regras separadas da coleta.** `RuleEngine` é uma classe pura que recebe o log e o horário, o que permite testar janela de tempo e cooldown sem esperar o relógio.

## Testes

```bash
npm test
```

O teste de integração sobe o coletor numa porta UDP real, envia mensagens nos três formatos, e confere gravação, alerta e consultas pela API.

## Próximos passos

- Recepção via TCP e TLS (RFC 5425).
- Painel web com atualização em tempo real.
- Agrupar inserções em lote para volumes maiores.

## Licença

MIT
