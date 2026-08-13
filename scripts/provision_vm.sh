#!/usr/bin/env bash
#
# provision_vm.sh
# ----------------
# Run this INSIDE the target Linux VM (deployed on Proxmox) as root/sudo.
# It installs Docker, creates the Blue Team SSH user on the custom port,
# deploys the lab via Docker Compose, and seeds the Blue Team logs.
#
# Usage:
#   sudo bash scripts/provision_vm.sh
#
set -euo pipefail

SSH_PORT=2275
BLUE_USER="analyst"
BLUE_PASS="blue_team_rocks"

echo "=== [1/5] Installing prerequisites ==="
apt-get update -y
apt-get install -y ca-certificates curl gnupg openssh-server ufw

echo "=== [2/5] Installing Docker Engine + Compose plugin ==="
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

echo "=== [3/5] Creating Blue Team SSH user '${BLUE_USER}' on port ${SSH_PORT} ==="
if ! id "${BLUE_USER}" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "${BLUE_USER}"
fi
echo "${BLUE_USER}:${BLUE_PASS}" | chpasswd

# Give the Blue Team read access to the forensic logs
mkdir -p /opt/admin/logs
usermod -aG "$(stat -c '%G' /opt/admin/logs 2>/dev/null || echo root)" "${BLUE_USER}" || true
chmod -R 750 /opt/admin/logs || true

SSHD_CONFIG="/etc/ssh/sshd_config"
if ! grep -qE "^Port ${SSH_PORT}\$" "${SSHD_CONFIG}"; then
  sed -i "s/^#\?Port .*/Port ${SSH_PORT}/" "${SSHD_CONFIG}" 2>/dev/null || true
  if ! grep -q "^Port ${SSH_PORT}$" "${SSHD_CONFIG}"; then
    echo "Port ${SSH_PORT}" >> "${SSHD_CONFIG}"
  fi
fi
systemctl restart sshd || systemctl restart ssh

echo "=== [4/5] Opening firewall ports (${SSH_PORT}/tcp, 3075/tcp) ==="
ufw allow "${SSH_PORT}"/tcp || true
ufw allow 3075/tcp || true
echo "y" | ufw enable || true

echo "=== [5/5] Deploying the lab via Docker Compose ==="
cd "$(dirname "${BASH_SOURCE[0]}")/.."
docker compose up -d --build

echo "=== Seeding Blue Team forensic logs ==="
bash scripts/generate_logs.sh

cat <<EOF

============================================================
 SCENARIO75 lab deployed.
 Web app:  http://<vm-ip>:3075
 SSH (Blue Team): ssh ${BLUE_USER}@<vm-ip> -p ${SSH_PORT}
 Logs:     /opt/admin/logs (access.log, error.log)
============================================================
EOF
