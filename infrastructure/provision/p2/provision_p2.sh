#!/usr/bin/env bash
set -euo pipefail

# P2: Privilege Escalation via SUID-root buffer overflow
# Run this as root inside the Ubuntu VM.

# 1) Ensure build toolchain exists (no updates)
if ! command -v gcc >/dev/null 2>&1; then
  echo "[!] gcc not found. Install build-essential before running this script."
  exit 1
fi

# 2) Create target directory
mkdir -p /home/p1/p2
chown -R p1:p1 /home/p1/p2

# 3) Install vulnerable source
cat > /home/p1/p2/p2.c <<'SRC'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void win(void) {
    setuid(0);
    setgid(0);
    system("/bin/sh");
}

static void vuln(void) {
    char buf[64];
    puts("Enter input:");
    gets(buf);
}

int main(void) {
    vuln();
    return 0;
}
SRC

# 4) Compile with protections disabled (classic overflow)
gcc -fno-stack-protector -z execstack -no-pie -o /home/p1/p2/p2 /home/p1/p2/p2.c

# 5) Make SUID-root
chown root:root /home/p1/p2/p2
chmod 4755 /home/p1/p2/p2

# 5b) Remove source so students only see the binary
rm -f /home/p1/p2/p2.c

# 6) Extend per-boot flag generator to include P2
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

# Derive flags using the per-boot key
KEY=$(cat "$KEY_FILE")
FLAG_P1=$(printf '%s' "P1:$KEY" | sha256sum | awk '{print $1}')
FLAG_P2=$(printf '%s' "P2:$KEY" | sha256sum | awk '{print $1}')

# Write P1 flag
install -d -m 700 -o p1 -g p1 /home/p1/flags
printf '%s\n' "$FLAG_P1" > /home/p1/flags/flag_p1.txt
chown p1:p1 /home/p1/flags/flag_p1.txt
chmod 600 /home/p1/flags/flag_p1.txt

# Write P2 flag
printf '%s\n' "$FLAG_P2" > /root/flag_p2.txt
chmod 600 /root/flag_p2.txt
BOOT
  chmod 750 /opt/ctf/boot-keygen.sh
  chown root:root /opt/ctf/boot-keygen.sh
  systemctl restart ctf-bootkey.service || true
fi

# 7) Extend ctf-extract to support P1/P2 and key.txt
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
case "$PROBLEM" in
  P1) FLAG_PATH=/home/p1/flags/flag_p1.txt ;;
  P2) FLAG_PATH=/root/flag_p2.txt ;;
  *) echo "Usage: ctf-extract P1|P2"; exit 1 ;;
esac

if [[ ! -r "$FLAG_PATH" ]]; then
  echo "[!] Cannot read flag. You do not yet have required access."
  exit 1
fi

cat > flag.txt <<EOF
$(cat "$FLAG_PATH")
EOF

cat > key.txt <<EOF
$KEY
EOF

echo "Wrote flag.txt, key.txt"
EXTRACT
  chmod 755 /usr/local/bin/ctf-extract
  chown root:root /usr/local/bin/ctf-extract
fi

echo "P2 provisioned. SUID binary at /home/p1/p2/p2"
