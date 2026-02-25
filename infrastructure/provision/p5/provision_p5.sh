#!/usr/bin/env bash
set -euo pipefail

# P5: CSS hijacking with local Firefox over VNC
# Run this as root inside the Ubuntu VM.

# 1) Ensure required packages exist (no updates)
# NOTE: Install step is intentionally disabled. Packages are preinstalled in the VM.
# export DEBIAN_FRONTEND=noninteractive
# export NEEDRESTART_MODE=a
# echo "[P5] Installing desktop/VNC packages (may take a few minutes)..."
# timeout 1200 apt -y -qq install \
#   -o Dpkg::Options::=--force-confdef \
#   -o Dpkg::Options::=--force-confold \
#   -o Acquire::Retries=3 \
#   -o Acquire::http::Timeout=20 \
#   -o Acquire::https::Timeout=20 \
#   python3 python3-venv python3-pip \
#   xfce4 xfce4-goodies tigervnc-standalone-server tigervnc-common \
#   firefox dbus-x11 xterm || true

# 2) Ensure ctfadmin exists
if ! id -u ctfadmin >/dev/null 2>&1; then
  sudo useradd -m -s /bin/bash ctfadmin
  echo "ctfadmin:changeme" | chpasswd
fi
# Ensure ctfadmin is not a sudo user (no supplemental groups beyond its own)
usermod -G ctfadmin ctfadmin

# 3) Create P5 directories
mkdir -p /opt/p5
chown -R ctfadmin:ctfadmin /opt/p5
chmod 755 /opt/p5

# 4) Install server
install -m 755 -o root -g root /vagrant/p5/server.py /opt/p5/server.py

# 5) Create CSS file placeholder
if [[ ! -f /opt/p5/user.css ]]; then
  echo "/* submit CSS to reveal the flag */" > /opt/p5/user.css
fi
chown ctfadmin:ctfadmin /opt/p5/user.css
chmod 644 /opt/p5/user.css

# Browser note: use epiphany-browser inside VNC (preinstalled in the VM).

# 6) Systemd service for P5 server
cat > /etc/systemd/system/p5-server.service <<'UNIT'
[Unit]
Description=P5 CSS Challenge Server
After=network.target

[Service]
Type=simple
User=ctfadmin
WorkingDirectory=/opt/p5
ExecStart=/usr/bin/python3 /opt/p5/server.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

systemctl enable p5-server.service
timeout 15 systemctl restart p5-server.service || true

# 7) VNC setup for ctfadmin
install -d -m 700 -o ctfadmin -g ctfadmin /home/ctfadmin/.vnc
CTFADMIN_UID=$(id -u ctfadmin)
install -d -m 700 -o ctfadmin -g ctfadmin "/run/user/${CTFADMIN_UID}"

# VNC password (default: ctfadmin)
if [[ ! -f /home/ctfadmin/.vnc/passwd ]]; then
  printf "ctfadmin\n" | /usr/bin/vncpasswd -f > /home/ctfadmin/.vnc/passwd || true
fi
chown ctfadmin:ctfadmin /home/ctfadmin/.vnc/passwd
chmod 600 /home/ctfadmin/.vnc/passwd

# Xfce startup
touch /home/ctfadmin/.Xresources
chown ctfadmin:ctfadmin /home/ctfadmin/.Xresources
cat > /home/ctfadmin/.vnc/xstartup <<'XSTART'
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
if [ ! -d "$XDG_RUNTIME_DIR" ]; then
  mkdir -p "$XDG_RUNTIME_DIR"
  chmod 700 "$XDG_RUNTIME_DIR"
fi
if [ -f "$HOME/.Xresources" ]; then
  xrdb "$HOME/.Xresources"
fi
exec dbus-launch --exit-with-session startxfce4
XSTART
chmod 755 /home/ctfadmin/.vnc/xstartup
chown ctfadmin:ctfadmin /home/ctfadmin/.vnc/xstartup

# 8) Systemd service for VNC
cat > /etc/systemd/system/vncserver@.service <<'UNIT'
[Unit]
Description=VNC Server for %i
After=network.target

[Service]
Type=simple
User=ctfadmin
Group=ctfadmin
WorkingDirectory=/home/ctfadmin
ExecStart=/usr/bin/vncserver :%i -localhost no -geometry 1280x800 -depth 24 -fg
ExecStop=/usr/bin/vncserver -kill :%i
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable vncserver@1.service
timeout 15 systemctl restart vncserver@1.service || true

# 8b) Firefox wrapper for VNC sessions (avoids sandbox/memlock issues)
cat > /usr/local/bin/firefox-vnc <<'FF'
#!/usr/bin/env bash
set -euo pipefail
export MOZ_DISABLE_CONTENT_SANDBOX=1
export MOZ_DISABLE_GMP_SANDBOX=1
export MOZ_DISABLE_GPU_SANDBOX=1
exec /usr/bin/firefox -no-remote -profile /tmp/ff-vnc "$@"
FF
chmod 755 /usr/local/bin/firefox-vnc

# 9) Extend per-boot flag generator to include P5
if [[ -f /opt/ctf/boot-keygen.sh ]]; then
  cat > /opt/ctf/boot-keygen.sh <<'BOOT'
#!/usr/bin/env bash
set -euo pipefail

# Generate per-boot key for P1 user
install -d -m 700 -o p1 -g p1 /home/p1/.keys
KEY_FILE=/home/p1/.keys/boot.key
head -c 32 /dev/urandom | base64 > "$KEY_FILE"
chown p1:p1 "$KEY_FILE"
chmod 600 "$KEY_FILE"

# Clear per-boot solved markers
rm -f /opt/p3/solved /opt/p4/solved /opt/p5/solved 2>/dev/null || true

# Derive flags using the per-boot key
KEY=$(cat "$KEY_FILE")
FLAG_P1=$(printf '%s' "P1:$KEY" | sha256sum | awk '{print $1}')
FLAG_P2=$(printf '%s' "P2:$KEY" | sha256sum | awk '{print $1}')
FLAG_P3=$(printf '%s' "P3:$KEY" | sha256sum | awk '{print $1}')
FLAG_P4=$(printf '%s' "P4:$KEY" | sha256sum | awk '{print $1}')
FLAG_P5=$(printf '%s' "P5:$KEY" | sha256sum | awk '{print $1}')

# Write P1 flag
install -d -m 700 -o p1 -g p1 /home/p1/flags
printf '%s\n' "$FLAG_P1" > /home/p1/flags/flag_p1.txt
chown p1:p1 /home/p1/flags/flag_p1.txt
chmod 600 /home/p1/flags/flag_p1.txt

# Write P2 flag
printf '%s\n' "$FLAG_P2" > /root/flag_p2.txt
chmod 600 /root/flag_p2.txt

# Write P3 flag
install -d -m 755 -o p3flag -g p3flag /opt/p3
printf '%s\n' "$FLAG_P3" > /opt/p3/flag_p3.txt
chown p3flag:p3flag /opt/p3/flag_p3.txt
chmod 600 /opt/p3/flag_p3.txt

# Write P4 flag
install -d -m 755 -o p4flag -g p4flag /opt/p4
printf '%s\n' "$FLAG_P4" > /opt/p4/flag_p4.txt
chown p4flag:p4flag /opt/p4/flag_p4.txt
chmod 600 /opt/p4/flag_p4.txt

# Write P5 flag (ctfadmin)
install -d -m 700 -o ctfadmin -g ctfadmin /home/ctfadmin/flags
printf '%s\n' "$FLAG_P5" > /home/ctfadmin/flags/flag_p5.txt
chown ctfadmin:ctfadmin /home/ctfadmin/flags/flag_p5.txt
chmod 600 /home/ctfadmin/flags/flag_p5.txt
BOOT
  chmod 750 /opt/ctf/boot-keygen.sh
  chown root:root /opt/ctf/boot-keygen.sh
  systemctl restart ctf-bootkey.service || true
fi

# 10) Extend ctf-extract to support P1-P5
if [[ -f /usr/local/bin/ctf-extract ]]; then
  cat > /usr/local/bin/ctf-extract <<'EXTRACT'
#!/usr/bin/env bash
set -euo pipefail

PROBLEM=${1:-P1}
KEY_FILE=/home/p1/.keys/boot.key

if [[ ! -r "$KEY_FILE" ]]; then
  echo "[!] Cannot read key file. You need P1 access."
  exit 1
fi

KEY=$(cat "$KEY_FILE")

FLAG_PATH=""
NEED_SOLVED=""
COMPUTE_FLAG="0"
COMPUTE_TAG=""
case "$PROBLEM" in
  P1) FLAG_PATH=/home/p1/flags/flag_p1.txt ;;
  P2) FLAG_PATH=/root/flag_p2.txt ;;
  P3) NEED_SOLVED=/opt/p3/solved; COMPUTE_FLAG="1"; COMPUTE_TAG="P3" ;;
  P4) NEED_SOLVED=/opt/p4/solved; COMPUTE_FLAG="1"; COMPUTE_TAG="P4" ;;
  P5) NEED_SOLVED=/opt/p5/solved; COMPUTE_FLAG="1"; COMPUTE_TAG="P5" ;;
  *) echo "Usage: ctf-extract P1|P2|P3|P4|P5"; exit 1 ;;
esac

if [[ -n "$NEED_SOLVED" ]] && [[ ! -r "$NEED_SOLVED" ]]; then
  echo "[!] ${PROBLEM} not solved yet. Complete the ${PROBLEM} task first."
  exit 1
fi

if [[ "$COMPUTE_FLAG" == "1" ]]; then
  FLAG=$(printf '%s' "${COMPUTE_TAG}:${KEY}" | sha256sum | awk '{print $1}')
elif [[ -r "$FLAG_PATH" ]]; then
  FLAG=$(cat "$FLAG_PATH")
else
  echo "[!] Cannot read flag. You do not yet have required access."
  exit 1
fi

cat > flag.txt <<EOF
$FLAG
EOF

cat > key.txt <<EOF
$KEY
EOF

echo "Wrote flag.txt, key.txt"
EXTRACT
  chmod 755 /usr/local/bin/ctf-extract
  chown root:root /usr/local/bin/ctf-extract
fi

echo "P5 provisioned. Server at http://127.0.0.1:5005 and VNC on :1"
