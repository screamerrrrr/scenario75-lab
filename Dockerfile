FROM node:20-alpine

LABEL description="SCENARIO75 - Intentionally vulnerable Admin Feedback System. Lab use only."

WORKDIR /usr/src/app

COPY app/package.json ./
RUN npm install --omit=dev

COPY app/ ./

ENV PORT=3075
ENV LOG_DIR=/opt/admin/logs

RUN mkdir -p /opt/admin/logs

EXPOSE 3075

CMD ["node", "server.js"]
