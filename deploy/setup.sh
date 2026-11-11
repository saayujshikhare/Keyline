#!/usr/bin/env bash
# Installs Keyline on a fresh Ubuntu server (tested design target: Oracle Cloud Always Free, Ubuntu 22.04/24.04).
# Run as root from the unzipped keyline folder:   sudo bash deploy/setup.sh [hostname]
# With no hostname it uses <your-public-ip>.sslip.io, a free name that already points at your IP,
# so Caddy can get a real HTTPS certificate with no domain purchase.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"

IP="$(curl -fsS https://api.ipify.org)"
HOST="${1:-${IP//./-}.sslip.io}"
echo "Public IP: $IP   Site name: $HOST"

apt-get update -y
apt-get install -y curl ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https iptables

# Node.js 22
if ! node -v 2>/dev/null | grep -q '^v22'; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi

# Caddy (automatic HTTPS)
if ! command -v caddy >/dev/null; then
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy.gpg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt | sed 's#^deb #deb [signed-by=/usr/share/keyrings/caddy.gpg] #' > /etc/apt/sources.list.d/caddy.list
  apt-get update -y
  apt-get install -y caddy
fi

# App, run by an unprivileged user
id keyline >/dev/null 2>&1 || useradd --system --home /var/lib/keyline --shell /usr/sbin/nologin keyline
mkdir -p /opt/keyline /var/lib/keyline /etc/keyline
rm -rf /opt/keyline/lib /opt/keyline/public
cp -r "$SRC/server.js" "$SRC/package.json" "$SRC/lib" "$SRC/public" /opt/keyline/
chown -R root:root /opt/keyline
chown keyline:keyline /var/lib/keyline && chmod 700 /var/lib/keyline

# The pepper lives apart from the database, readable only by root (systemd passes it to the app)
if [ ! -f /etc/keyline/env ]; then
  umask 077
  echo "MSGR_PEPPER=$(openssl rand -hex 32)" > /etc/keyline/env
  echo "Generated /etc/keyline/env. BACK UP its contents somewhere safe: if it is lost, nobody can log in."
fi
chmod 600 /etc/keyline/env

cp "$SRC/deploy/keyline.service" /etc/systemd/system/keyline.service
sed "s/__HOST__/$HOST/" "$SRC/deploy/Caddyfile" > /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl enable --now keyline
systemctl restart caddy

# Oracle's Ubuntu images block everything but SSH in iptables: open web ports
for p in 80 443; do
  iptables -C INPUT -p tcp --dport $p -j ACCEPT 2>/dev/null || iptables -I INPUT 5 -p tcp --dport $p -j ACCEPT
done
if command -v netfilter-persistent >/dev/null; then netfilter-persistent save; else
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent && netfilter-persistent save
fi

sleep 2
systemctl is-active keyline caddy
echo
echo "Done. Open https://$HOST"
echo "If it does not load, add ingress rules for TCP 80 and 443 to the VM's subnet Security List in the Oracle console."
