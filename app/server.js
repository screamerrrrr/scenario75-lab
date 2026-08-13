/**
 * server.js
 * ---------
 * SCENARIO75: "Cookies Reuse & MFA Bypass"
 * Intentionally vulnerable "Admin Feedback System".
 *
 * ############################################################
 * # WARNING: This application is INTENTIONALLY VULNERABLE.   #
 * # Deploy ONLY inside an isolated lab / internal range VM.   #
 * # Never expose to the public internet.                      #
 * ############################################################
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { wafMiddleware } = require('./waf');
const logger = require('./logger');

logger.ensureLogDir();

const app = express();
const PORT = process.env.PORT || 3075;

app.disable('x-powered-by');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(logger.accessRequestMiddleware);

// Explicitly expose backend technology (Phase 1: Reconnaissance)
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'Node.js');
  next();
});

// In-memory "database" of admin feedback entries (stored reflected XSS sink)
const feedbackEntries = [];

// Demo credentials for the legitimate MFA-gated admin login flow
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin123';
const DEMO_OTP = '123456';

// ---------------------------------------------------------------------
// PHASE 1: RECONNAISSANCE
// ---------------------------------------------------------------------

app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(
    [
      'User-agent: *',
      'Disallow: /api/verify-mfa',
      'Disallow: /dashboard',
      ''
    ].join('\n')
  );
});

app.get('/', (req, res) => {
  // Session Initialization: pre-authentication cookie, HttpOnly explicitly FALSE
  res.cookie('pre_mfa_session', 'pending_mfa_verification', {
    httpOnly: false,
    path: '/'
  });

  res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Corporate Admin Feedback System</title>
  <!--
     _____                _ _                _
    |  ___|__  ___  __ _  | |__   __ _  ___| | __
    | |_ / _ \\/ _ \\/ _\` | | '_ \\ / _\` |/ __| |/ /
    |  _|  __/  __/ (_| | | |_) | (_| | (__|   <
    |_|  \\___|\\___|\\__,_| |_.__/ \\__,_|\\___|_|\\_\\

    Psst, curious minds... every good recon starts with robots.txt ;)
  -->
  <style>
    body{font-family:Arial,sans-serif;max-width:640px;margin:60px auto;color:#222}
    textarea{width:100%;height:120px}
    input,button{padding:8px;margin-top:8px}
  </style>
</head>
<body>
  <h1>Admin Feedback System</h1>
  <p>Submit feedback for the administration team. All submissions are reviewed by an admin.</p>
  <form id="fbForm">
    <label>Name: <input type="text" id="name" name="name"></label><br>
    <label>Message:</label><br>
    <textarea id="message" name="message"></textarea><br>
    <button type="submit">Submit Feedback</button>
  </form>
  <p id="result"></p>
  <script>
    document.getElementById('fbForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('name').value;
      const message = document.getElementById('message').value;
      const res = await fetch('/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, message })
      });
      const data = await res.json();
      document.getElementById('result').innerText = res.status + ': ' + JSON.stringify(data);
    });
  </script>
</body>
</html>`);
});

// ---------------------------------------------------------------------
// PHASE 2: DEFENSE EVASION (WAF & STORED XSS)
// ---------------------------------------------------------------------

app.post('/feedback', wafMiddleware(logger), (req, res) => {
  const { name, message } = req.body || {};

  if (!message) {
    return res.status(400).json({ error: 'message is required' });
  }

  feedbackEntries.push({
    id: crypto.randomUUID(),
    name: name || 'anonymous',
    message,
    submittedAt: new Date().toISOString()
  });

  res.status(200).json({ status: 'received', message: 'Thank you for your feedback.' });
});

// ---------------------------------------------------------------------
// LEGITIMATE ADMIN LOGIN FLOW (the "correct" path, for contrast)
// ---------------------------------------------------------------------

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    return res.status(200).json({ status: 'credentials_ok', next: '/api/verify-mfa' });
  }
  return res.status(401).json({ error: 'invalid credentials' });
});

app.post('/api/verify-mfa', (req, res) => {
  const { otp } = req.body || {};

  if (otp !== DEMO_OTP) {
    logger.errorLine('WARN', `Failed MFA attempt ip=${req.ip}`);
    return res.status(401).json({ error: 'invalid OTP' });
  }

  // Only the legitimate path issues a fresh adm_sess-prefixed cookie
  const sessionId = 'adm_sess_' + crypto.randomBytes(16).toString('hex');
  res.cookie(sessionId, 'authenticated', { httpOnly: true, path: '/' });
  res.cookie('adm_sess_marker', sessionId, { httpOnly: true, path: '/' });

  logger.errorLine('INFO', `MFA verified successfully ip=${req.ip} session=${sessionId}`);
  res.status(200).json({ status: 'mfa_verified', dashboard: '/dashboard' });
});

// ---------------------------------------------------------------------
// PHASE 3: INITIAL ACCESS (THE VULNERABILITY)
// ---------------------------------------------------------------------
//
// THE BUG: /dashboard only checks for the *presence* of any cookie whose
// name starts with "adm_sess". It never validates that /api/verify-mfa
// was actually called for *this* client, and it never binds the session
// to the issuing browser/device. Combined with the pre_mfa_session cookie
// being HttpOnly=false (stealable via XSS) and the admin session cookie
// carrying a guessable/static-looking prefix, an attacker who steals ANY
// valid adm_sess_* cookie (e.g. via the stored XSS in /feedback) can
// replay it directly against /dashboard and skip MFA entirely.

function hasAdminSessionCookie(req) {
  return Object.keys(req.cookies || {}).some((name) => name.startsWith('adm_sess'));
}

app.get('/dashboard', (req, res) => {
  if (!hasAdminSessionCookie(req)) {
    return res.status(401).send('401 Unauthorized - admin session required');
  }

  // VULNERABLE: no re-verification against /api/verify-mfa happens here.
  const feedbackHtml = feedbackEntries
    .map(
      (f) => `
    <div class="feedback-item">
      <strong>${f.name}</strong> (${f.submittedAt})
      <div class="xss-payload">${f.message}</div>
    </div>`
    )
    .join('\n');

  res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Admin Dashboard</title>
  <style>
    body{font-family:Arial,sans-serif;max-width:720px;margin:40px auto;color:#222}
    .feedback-item{border:1px solid #ddd;padding:10px;margin:10px 0;border-radius:6px}
  </style>
</head>
<body>
  <h1>Administrative Dashboard</h1>
  <p>Restricted area. Reviewing citizen/employee feedback below.</p>
  <div id="feedback-list">
    ${feedbackHtml || '<p>No feedback submitted yet.</p>'}
  </div>

  <!-- FLAG: SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d} -->
</body>
</html>`);
});

// ---------------------------------------------------------------------
// SIMULATED ATTACKER COLLECTOR (in-lab, for a self-contained exfil demo)
// ---------------------------------------------------------------------
// Represents the "attacker-controlled" endpoint that a stolen-cookie
// exfil payload (fetch(...)) would call. Kept inside the same app so the
// whole chain is demonstrable without external infrastructure.
app.get('/collect', (req, res) => {
  logger.errorLine(
    'CRITICAL',
    `Cookie reuse / exfiltration detected ip=${req.ip} xff="${req.get('X-Forwarded-For') || '-'}" data="${req.query.data || ''}"`
  );
  res.status(200).send('ok');
});

app.listen(PORT, () => {
  console.log(`[SCENARIO75] Admin Feedback System listening on port ${PORT}`);
});
