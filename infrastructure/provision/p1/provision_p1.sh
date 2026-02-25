#!/usr/bin/env bash
set -euo pipefail

# P1: Gain Access (info leak -> SSH)
# Run this as root inside the Ubuntu VM.

# 1) Ensure required packages (quiet, idempotent)
# Do not run apt update/upgrade as requested.
export DEBIAN_FRONTEND=noninteractive
apt -y -qq install openssh-server nginx >/dev/null || true

# 2) Create user p1 if not exists
if ! id -u p1 >/dev/null 2>&1; then
  useradd -m -s /bin/bash p1
  echo "p1:changeme" | chpasswd
fi

# 3) Generate SSH key pair for p1 (no passphrase)
install -d -m 700 -o p1 -g p1 /home/p1/.ssh
if [[ ! -f /home/p1/.ssh/id_rsa ]]; then
  sudo -u p1 ssh-keygen -t rsa -b 2048 -f /home/p1/.ssh/id_rsa -N ""
fi

# 4) Add public key to authorized_keys
if ! grep -qF "$(cat /home/p1/.ssh/id_rsa.pub)" /home/p1/.ssh/authorized_keys 2>/dev/null; then
  sudo -u p1 bash -c 'cat /home/p1/.ssh/id_rsa.pub >> /home/p1/.ssh/authorized_keys'
fi
chmod 600 /home/p1/.ssh/authorized_keys
chown p1:p1 /home/p1/.ssh/authorized_keys

# 5) Leak private key via web server (misconfiguration)
mkdir -p /var/www/html/backup
cp /home/p1/.ssh/id_rsa /var/www/html/backup/id_rsa
chmod 644 /var/www/html/backup/id_rsa

# 5b) Add decoy web directory with fake keys
mkdir -p /var/www/html/old_keys
if [[ ! -f /var/www/html/old_keys/id_rsa.old ]]; then
  ssh-keygen -t rsa -b 2048 -f /var/www/html/old_keys/id_rsa.old -N "" >/dev/null
fi
chmod 644 /var/www/html/old_keys/id_rsa.old
chmod 644 /var/www/html/old_keys/id_rsa.old.pub

# 5c) Add robots.txt hint for discovery
cat > /var/www/html/robots.txt <<'TXT'
User-agent: *
Disallow: /backup/
Disallow: /old_keys/
TXT
chmod 644 /var/www/html/robots.txt

# 6) Start nginx
systemctl enable nginx
systemctl restart nginx

# 7) Start ssh
systemctl enable ssh
systemctl restart ssh

# 8) Per-boot key and P1 flag generation
mkdir -p /opt/ctf
cat > /opt/ctf/boot-keygen.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail

# Generate per-boot key for P1 user
install -d -m 700 -o p1 -g p1 /home/p1/.keys
KEY_FILE=/home/p1/.keys/boot.key
head -c 32 /dev/urandom | base64 > "$KEY_FILE"
chown p1:p1 "$KEY_FILE"
chmod 600 "$KEY_FILE"

# Derive P1 flag using the per-boot key
KEY=$(cat "$KEY_FILE")
FLAG_P1=$(printf '%s' "P1:$KEY" | sha256sum | awk '{print $1}')

# Write P1 flag to protected location
install -d -m 700 -o p1 -g p1 /home/p1/flags
printf '%s\n' "$FLAG_P1" > /home/p1/flags/flag_p1.txt
chown p1:p1 /home/p1/flags/flag_p1.txt
chmod 600 /home/p1/flags/flag_p1.txt
SH

chmod 750 /opt/ctf/boot-keygen.sh
chown root:root /opt/ctf/boot-keygen.sh

cat > /etc/systemd/system/ctf-bootkey.service <<'UNIT'
[Unit]
Description=CTF per-boot key and P1 flag generator
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/ctf/boot-keygen.sh

[Install]
WantedBy=multi-user.target
UNIT

systemctl enable ctf-bootkey.service
systemctl start ctf-bootkey.service

# 9) Extraction helper (P1 only)
cat > /usr/local/bin/ctf-extract <<'SH'
#!/usr/bin/env bash
set -euo pipefail

KEY_FILE=/home/p1/.keys/boot.key
FLAG_PATH=/home/p1/flags/flag_p1.txt

if [[ ! -r "$KEY_FILE" ]]; then
  echo "[!] Cannot read key file. You need P1 access."
  exit 1
fi

if [[ ! -r "$FLAG_PATH" ]]; then
  echo "[!] Cannot read flag. You do not yet have required access."
  exit 1
fi

KEY=$(cat "$KEY_FILE")

cat > flag.txt <<EOF
$(cat "$FLAG_PATH")
EOF

cat > key.txt <<EOF
$KEY
EOF

echo "Wrote flag.txt, key.txt"
SH

chmod 755 /usr/local/bin/ctf-extract
chown root:root /usr/local/bin/ctf-extract

# 8) MOTD hint (short, subtle)
MOTD_FILE=/etc/motd
HINT="Tip: check what the web server might be sharing that it shouldn't."
if ! grep -qF "$HINT" "$MOTD_FILE" 2>/dev/null; then
  echo "$HINT" >> "$MOTD_FILE"
fi

echo "P1 provisioned. Leaked key at /backup/id_rsa over HTTP."
