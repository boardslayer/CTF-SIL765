# NSS A2 Single-VM CTF Build Guide (Ubuntu Server + VirtualBox)

This document is a comprehensive, step-by-step build guide for a single Ubuntu VM image that supports all five problems (P1–P5) in the assignment. It is written so you can reproduce the VM on an ARM64 host now and replicate on AMD64 later.

Important instructor note satisfied:
- All flags depend on a per-boot key stored in the P1 user’s profile.
- The key is regenerated on every VM reboot.
- Students are instructed to re-extract flag files each time they decide on a solution.

The guidance below is split into:
1. VM creation and OS install
2. Base system configuration
3. Flag and keying system
4. Problem-specific setup (P1–P5)
5. Validation checklist
6. Student-facing run notes

---

## 1) VM Creation and OS Install (VirtualBox)

### 1.1 Create VM
Use VirtualBox to create a new VM:
- Name: `NSS-A2-CTF`
- Type: `Linux`
- Version: `Ubuntu (64-bit)`
- RAM: `2–4 GB`
- CPU: `2 cores`
- Disk: `20 GB` (VDI, dynamically allocated)
- vagrant password changed to 'vagrantpassword' for instructor testing

Network:
- Adapter 1: NAT
- Port forwarding:
  - Host 2222 -> Guest 22 (SSH)
  - Host 8000 -> Guest 80 (HTTP)
  - Optional decoy forwards (not used by services):
    - Host 9001 -> Guest 9001
    - Host 9002 -> Guest 9002

### 1.2 Attach ISO
Attach the provided ISO:
- `ubuntu-22.04.5-live-server-arm64.iso`

Note: This is ARM64-only. Use the AMD64 ISO later when you replicate on Intel/AMD hosts.

### 1.3 Install Ubuntu Server
During install:
- Create user `ctfadmin`
- Enable OpenSSH server
- Skip snaps if you prefer minimal base

After install, update and install base packages:
```bash
sudo apt update
sudo apt -y upgrade
sudo apt -y install openssh-server nginx build-essential gdb python3 python3-pip net-tools socat \
  python3 python3-venv python3-pip \
  xfce4 xfce4-goodies tigervnc-standalone-server tigervnc-common \
  dbus-x11 xterm epiphany-browser
```

---

## 2) Base System Configuration

### 2.1 Create Users
Create the main vulnerable user (P1) and problem flag users:
```bash
sudo useradd -m -s /bin/bash p1
sudo useradd -m -s /bin/bash p3flag
sudo useradd -m -s /bin/bash p4flag
```
Set passwords (choose simple ones for instructor testing; students will not be told):
```bash
sudo passwd p1
sudo passwd p3flag
sudo passwd p4flag
```

### 2.2 SSH
Ensure SSH is enabled and running:
```bash
sudo systemctl enable ssh
sudo systemctl restart ssh
```

### 2.3 Disable ASLR (for P4)
Create a sysctl override:
```bash
echo 'kernel.randomize_va_space=0' | sudo tee /etc/sysctl.d/01-disable-aslr.conf
sudo sysctl -p /etc/sysctl.d/01-disable-aslr.conf
```

---

## 3) Flag and Keying System (Per-Boot Key)

We store a per-boot secret key in `/home/p1/.keys/boot.key`. A boot-time service regenerates it and uses it to derive flags for P1–P5, then writes those flags into protected locations (with correct permissions).

### 3.1 Boot Key and Flag Generator Script
Create a script that runs on boot:
```bash
sudo mkdir -p /opt/ctf
sudo tee /opt/ctf/boot-keygen.sh > /dev/null <<'SH'
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

# Write flags to protected locations
# P1 flag in p1 home (readable by p1)
install -d -m 700 -o p1 -g p1 /home/p1/flags
printf '%s\n' "$FLAG_P1" > /home/p1/flags/flag_p1.txt
chown p1:p1 /home/p1/flags/flag_p1.txt
chmod 600 /home/p1/flags/flag_p1.txt

# P2 flag in root home (readable by root)
printf '%s\n' "$FLAG_P2" > /root/flag_p2.txt
chmod 600 /root/flag_p2.txt

# P3 flag owned by p3flag
install -d -m 700 -o p3flag -g p3flag /opt/p3
printf '%s\n' "$FLAG_P3" > /opt/p3/flag_p3.txt
chown p3flag:p3flag /opt/p3/flag_p3.txt
chmod 600 /opt/p3/flag_p3.txt

# P4 flag owned by p4flag
install -d -m 700 -o p4flag -g p4flag /opt/p4
printf '%s\n' "$FLAG_P4" > /opt/p4/flag_p4.txt
chown p4flag:p4flag /opt/p4/flag_p4.txt
chmod 600 /opt/p4/flag_p4.txt

# P5 flag owned by ctfadmin
install -d -m 700 -o ctfadmin -g ctfadmin /home/ctfadmin/flags
printf '%s\n' "$FLAG_P5" > /home/ctfadmin/flags/flag_p5.txt
chown ctfadmin:ctfadmin /home/ctfadmin/flags/flag_p5.txt
chmod 600 /home/ctfadmin/flags/flag_p5.txt
SH

sudo chmod 750 /opt/ctf/boot-keygen.sh
sudo chown root:root /opt/ctf/boot-keygen.sh
```

### 3.2 Systemd Service
Create a systemd unit to run at boot:
```bash
sudo tee /etc/systemd/system/ctf-bootkey.service > /dev/null <<'UNIT'
[Unit]
Description=CTF per-boot key and flag generator
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/ctf/boot-keygen.sh

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl enable ctf-bootkey.service
sudo systemctl start ctf-bootkey.service
```

### 3.3 Extraction Helper (Student-Facing)
Provide a helper that creates `flag.txt` and `key.txt` once the user has the required access. The helper will fail if the user does not have permission to read the protected flag file.

```bash
sudo tee /usr/local/bin/ctf-extract > /dev/null <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: ctf-extract P1|P2|P3|P4|P5"
  exit 1
fi

PROBLEM="$1"
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
  P3) FLAG_PATH=/opt/p3/flag_p3.txt ;;
  P4) FLAG_PATH=/opt/p4/flag_p4.txt ;;
  P5) FLAG_PATH=/home/ctfadmin/flags/flag_p5.txt ;;
  *) echo "Invalid problem"; exit 1 ;;
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
SH

sudo chmod 755 /usr/local/bin/ctf-extract
sudo chown root:root /usr/local/bin/ctf-extract
```

Instructor note: Students should run `ctf-extract P1|P2|P3|P4|P5` after solving each problem. Because keys are per-boot, they must extract again after every reboot.

---

## 4) Problem Setup

### P1: Gain Access (Info Leak -> SSH)
Goal: Obtain unprivileged shell as `p1` and read `/home/p1/flags/flag_p1.txt`.

#### P1 Setup
1. Create SSH key pair for `p1`:
```bash
sudo -u p1 ssh-keygen -t rsa -b 2048 -f /home/p1/.ssh/id_rsa -N ""
```
2. Add public key to authorized_keys:
```bash
sudo -u p1 bash -c 'cat /home/p1/.ssh/id_rsa.pub >> /home/p1/.ssh/authorized_keys'
sudo chmod 600 /home/p1/.ssh/authorized_keys
```
3. Leak private key via web server (misconfiguration):
```bash
sudo mkdir -p /var/www/html/backup
sudo cp /home/p1/.ssh/id_rsa /var/www/html/backup/id_rsa
sudo chmod 644 /var/www/html/backup/id_rsa
```
4. Ensure nginx is running:
```bash
sudo systemctl enable nginx
sudo systemctl restart nginx
```

Student attack path:
- Discover leaked private key at `http://<host>:8000/backup/id_rsa`
- Use it to SSH into the VM as `p1`

### P2: Become Super (SUID Root Buffer Overflow)
Goal: Exploit a local buffer overflow in a SUID-root binary to get root, then read `/root/flag_p2.txt`.

#### P2 Binary
Create vulnerable program:
```bash
sudo mkdir -p /home/p1/p2
sudo tee /home/p1/p2/p2.c > /dev/null <<'C'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() {
    setuid(0);
    setgid(0);
    system("/bin/sh");
}

void vuln() {
    char buf[64];
    puts("Enter input:");
    gets(buf);
}

int main() {
    vuln();
    return 0;
}
C

sudo gcc -fno-stack-protector -z execstack -no-pie -o /home/p1/p2/p2 /home/p1/p2/p2.c
sudo chown root:root /home/p1/p2/p2
sudo chmod 4755 /home/p1/p2/p2
```

### P3: Changing the Flow (NX, Ret2Win)
Goal: Redirect execution to `win()` and print `/opt/p3/flag_p3.txt`.

#### P3 Binary
```bash
sudo mkdir -p /home/p1/p3
sudo tee /home/p1/p3/p3.c > /dev/null <<'C'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void mark_solved(void) {
    FILE *f = fopen("/opt/p3/solved", "w");
    if (f) {
        fputs("ok\n", f);
        fclose(f);
    }
}

void win() {
    FILE *f = fopen("/opt/p3/flag_p3.txt", "r");
    if (!f) {
        puts("No flag");
        exit(1);
    }
    char flag[128];
    fgets(flag, sizeof(flag), f);
    printf("FLAG: %s\n", flag);
    fclose(f);
    mark_solved();
    exit(0);
}

void vuln() {
    char buf[64];
    puts("Say something:");
    gets(buf);
}

int main() {
    vuln();
    return 0;
}
C

sudo gcc -fno-stack-protector -no-pie -z noexecstack -o /home/p1/p3/p3 /home/p1/p3/p3.c
sudo chown p3flag:p3flag /home/p1/p3/p3
sudo chmod 4755 /home/p1/p3/p3
```

### P4: Format String (Auth Gate)
Goal: Use a format-string bug to flip an auth check and trigger `win()` to print `/opt/p4/flag_p4.txt`.

#### P4 Binary
```bash
sudo mkdir -p /home/p1/p4
sudo tee /home/p1/p4/p4.c > /dev/null <<'C'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
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

void safe(void) {
    puts("Nope.");
}

void (*fp)(void) = safe;

void vuln(void) {
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
C

sudo gcc -fno-stack-protector -no-pie -z noexecstack -o /home/p1/p4/p4 /home/p1/p4/p4.c
sudo chown p4flag:p4flag /home/p1/p4/p4
sudo chmod 4755 /home/p1/p4/p4
sudo rm -f /home/p1/p4/p4.c
```

### P5: CSS Hijacking (Epiphany + VNC)
Goal: Use CSS to reveal a hidden flag on the admin page and submit it.

#### P5 Server (runs on localhost)
- Server: `http://127.0.0.1:5005`
- Admin page: `http://127.0.0.1:5005/admin`
- CSS upload: `http://127.0.0.1:5005/submit`

#### P5 Setup Notes
- VNC server runs on `:1` (host port `5901`).
- Epiphany (`epiphany-browser`) is used for in‑VM browsing.
- The P5 flag is stored at `/home/ctfadmin/flags/flag_p5.txt` and injected into the admin page.
- VNC password is `ctfadmin` (change if desired).

## 5) Validation Checklist

Run these checks:
```bash
# P1
curl http://localhost:8000/backup/id_rsa
ssh -i /tmp/id_rsa -p 2222 p1@localhost

# P2
ls -l /home/p1/p2/p2  # should be rwsr-xr-x root root
file /home/p1/p2/p2   # should be ELF 64-bit, not PIE
```

Quick P2 exploit sanity check (as p1):
```bash
# Get win() address
nm -n /home/p1/p2/p2 | rg " win$"
# Then craft payload (offset may be 72 on x86_64):
# python3 -c 'print("A"*72 + "<addr>")' | /home/p1/p2/p2
```
Continue checks:
```bash

# P3
ls -l /home/p1/p3/p3  # should be rwsr-xr-x p3flag p3flag

# P4
ls -l /home/p1/p4/p4  # should be rwsr-xr-x p4flag p4flag

# Flags
sudo cat /root/flag_p2.txt
sudo -u p1 cat /home/p1/flags/flag_p1.txt
sudo -u p3flag cat /opt/p3/flag_p3.txt
sudo -u p4flag cat /opt/p4/flag_p4.txt
```

Test `ctf-extract`:
```bash
# As p1 (should succeed for P1 only)
ctf-extract P1

# As root (should succeed for P2)
sudo ctf-extract P2
```

---

## 6) Student-Facing Run Notes (Include in Assignment)

- VM runs on VirtualBox.
- Use NAT and connect over SSH (host port 2222 -> guest 22).
- P1: Find leaked SSH private key from web server, then SSH into VM.
- P2–P5: Use local exploitation on provided binaries/services.
- Flags change on every reboot. Run `ctf-extract P1|P2|P3|P4|P5` after solving each problem.

Submission (tar available, zip not required):
```bash
tar -czf 2022CSZ123456-P1.tar.gz flag.txt key.txt
```

Copy submission to host (from host terminal):
```bash
scp -P 2222 p1@localhost:/home/p1/2022CSZ123456-P1.tar.gz .
```

---

## 7) AMD64 Replication Notes

When you rebuild this VM for Intel/AMD hosts:
- Use the `ubuntu-22.04.5-live-server-amd64.iso` ISO instead.
- Repeat the exact configuration steps from this guide.

---

## 8) Security and Quality Notes (Instructor)

- These binaries are intentionally unsafe.
- Keep this VM isolated and do not expose it on public networks.
- Consider snapshotting the VM after setup.
