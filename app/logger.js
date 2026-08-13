/**
 * logger.js
 * ---------
 * Writes real-time telemetry into /opt/admin/logs so that live exploitation
 * of the running lab (not just the pre-seeded historical incident) also
 * produces forensic evidence for the Blue Team.
 *
 * access.log  -> nginx-combined-style access log
 * error.log   -> application-level security/error events
 */

const fs = require('fs');
const path = require('path');

const LOG_DIR = process.env.LOG_DIR || '/opt/admin/logs';
const ACCESS_LOG = path.join(LOG_DIR, 'access.log');
const ERROR_LOG = path.join(LOG_DIR, 'error.log');

function ensureLogDir() {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  if (!fs.existsSync(ACCESS_LOG)) fs.writeFileSync(ACCESS_LOG, '');
  if (!fs.existsSync(ERROR_LOG)) fs.writeFileSync(ERROR_LOG, '');
}

function ts() {
  return new Date().toISOString();
}

function appendLine(file, line) {
  fs.appendFile(file, line + '\n', (err) => {
    if (err) console.error('Failed to write log:', err.message);
  });
}

function accessLine({ ip, method, url, status, userAgent, xff }) {
  const line = `${ip} - - [${ts()}] "${method} ${url} HTTP/1.1" ${status} - "-" "${userAgent}"${xff ? ` X-Forwarded-For:"${xff}"` : ''}`;
  appendLine(ACCESS_LOG, line);
}

function errorLine(level, message) {
  const line = `[${ts()}] [${level}] ${message}`;
  appendLine(ERROR_LOG, line);
}

function wafBlock({ ip, userAgent, reason, payload }) {
  errorLine('WARN', `WAF BLOCK ip=${ip} ua="${userAgent}" reason="${reason}" payload=${payload}`);
}

function accessRequestMiddleware(req, res, next) {
  res.on('finish', () => {
    accessLine({
      ip: req.ip,
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      userAgent: req.get('User-Agent') || '-',
      xff: req.get('X-Forwarded-For')
    });
  });
  next();
}

module.exports = {
  ensureLogDir,
  accessLine,
  errorLine,
  wafBlock,
  accessRequestMiddleware,
  ACCESS_LOG,
  ERROR_LOG
};
