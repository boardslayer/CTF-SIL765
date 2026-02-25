#!/usr/bin/env bash
set -euo pipefail

# P4: Format-string vulnerability
# Run this as root inside the Ubuntu VM.

# 1) Ensure build toolchain exists (no updates)
if ! command -v gcc >/dev/null 2>&1; then
  echo "[!] gcc not found. Install build-essential before running this script."
  exit 1
fi

# 2) Ensure p4flag user exists
if ! id -u p4flag >/dev/null 2>&1; then
  useradd -m -s /bin/bash p4flag
  echo "p4flag:changeme" | chpasswd
fi

# 3) Create target directories
mkdir -p /home/p1/p4
chown -R p1:p1 /home/p1/p4
mkdir -p /opt/p4
chown -R p4flag:p4flag /opt/p4
chmod 755 /opt/p4

# 4) Install vulnerable source
cat > /home/p1/p4/p4.c <<'SRC'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void win(void) {
    FILE *f = fopen("/opt/p4/flag_p4.txt", "r");
    if (!f) {
        puts("No flag");
        exit(1);
    }
    char flag[128];
    if (fgets(flag, sizeof(flag), f) != NULL) {
        printf("FLAG: %s\n", flag);
    } else {
        puts("No flag");
    }
    fclose(f);
    FILE *s = fopen("/opt/p4/solved", "w");
    if (s) {
        fputs("ok\n", s);
        fclose(s);
    }
    exit(0);
}

static void safe(void) {
    puts("Nope.");
}

static void (*fp)(void) = safe;

static void vuln(void) {
    char buf[128];
    int auth = 0;
    int dummy = 0;
    puts("Input:");
    if (!fgets(buf, sizeof(buf), stdin)) {
        return;
    }
    printf(buf, &auth, dummy);
    if (auth == 0x1337) {
        fp = win;
    }
    fp();
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    setgid(getegid());
    setuid(geteuid());
    vuln();
    return 0;
}
SRC

# 5) Compile with NX enabled, no PIE, no canary
gcc -fno-stack-protector -no-pie -z noexecstack -o /home/p1/p4/p4 /home/p1/p4/p4.c

# 6) Make SUID to p4flag
chown p4flag:p4flag /home/p1/p4/p4
chmod 4755 /home/p1/p4/p4

# 6b) Remove source so students only see the binary
rm -f /home/p1/p4/p4.c

# 7) Extend per-boot flag generator to include P4
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
BOOT
  chmod 750 /opt/ctf/boot-keygen.sh
  chown root:root /opt/ctf/boot-keygen.sh
  systemctl restart ctf-bootkey.service || true
fi

# 8) Extend ctf-extract to support P1/P2/P3/P4 and key.txt
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
  *) echo "Usage: ctf-extract P1|P2|P3|P4"; exit 1 ;;
esac

if [[ -n "$NEED_SOLVED" ]] && [[ ! -r "$NEED_SOLVED" ]]; then
  echo "[!] ${PROBLEM} not solved yet. Exploit the ${PROBLEM} binary first."
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

echo "P4 provisioned. SUID binary at /home/p1/p4/p4"
