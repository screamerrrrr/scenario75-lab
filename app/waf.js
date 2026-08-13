/**
 * waf.js
 * ------
 * A deliberately "rudimentary" Web Application Firewall for SCENARIO75.
 *
 * Design intent (per assessment spec):
 *  - Blocks the naive <script> payload            -> 403
 *  - Does NOT understand other HTML5 event-handler vectors (e.g. <svg onload=...>)
 *  - Blocks the literal keyword "document.cookie"  -> 403
 *  - Does NOT understand bracket-notation obfuscation, e.g.
 *      window['docu'+'ment']['coo'+'kie']
 *
 * This is intentionally naive so the Red Team path (Phase 2) can be completed
 * with a classic keyword-blocklist bypass.
 */

const SCRIPT_TAG_PATTERN = /<\s*script\b/i;
const DOCUMENT_COOKIE_PATTERN = /document\s*\.\s*cookie/i;

function inspect(payload) {
  if (typeof payload !== 'string') return { blocked: false };

  if (SCRIPT_TAG_PATTERN.test(payload)) {
    return { blocked: true, reason: '<script> tag detected' };
  }
  if (DOCUMENT_COOKIE_PATTERN.test(payload)) {
    return { blocked: true, reason: 'literal document.cookie keyword detected' };
  }
  return { blocked: false };
}

function wafMiddleware(logger) {
  return (req, res, next) => {
    const candidate = JSON.stringify(req.body || {});
    const verdict = inspect(candidate);

    if (verdict.blocked) {
      if (logger) {
        logger.wafBlock({
          ip: req.ip,
          userAgent: req.get('User-Agent') || '-',
          reason: verdict.reason,
          payload: candidate
        });
      }
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Request blocked by WAF: ' + verdict.reason
      });
    }

    next();
  };
}

module.exports = { wafMiddleware, inspect };
