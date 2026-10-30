FROM node:22-alpine

WORKDIR /app
COPY package.json ./
COPY src ./src
COPY config ./config

ENV NODE_ENV=production \
    SYSLOG_PORT=5514 \
    HTTP_PORT=3000 \
    DB_PATH=/data/syslog.db

RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 5514/udp 3000

CMD ["node", "--disable-warning=ExperimentalWarning", "src/index.js"]
