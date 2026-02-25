# Flag Extraction Steps (P1–P5)

This document lists the exact commands to extract flags and generate the submission files for each problem.

## Common Notes
- Run these **inside the VM** unless noted.
- Flags are **per‑boot**. If the VM reboots, you must re‑run `ctf-extract` after solving again.
- `ctf-extract` writes `flag.txt` and `key.txt` in the **current directory**.

---

## Problem 1 (P1)
After you have access as `p1`:
```bash
ctf-extract P1
```
Package submission:
```bash
tar -czf 2022CSZ123456-P1.tar.gz flag.txt key.txt
```
Copy to host:
```bash
scp -P 2222 p1@localhost:/home/p1/2022CSZ123456-P1.tar.gz .
```

---

## Problem 2 (P2)
After you obtain a root shell (or have root access):
```bash
ctf-extract P2
```
Package submission:
```bash
tar -czf 2022CSZ123456-P2.tar.gz flag.txt key.txt
```
Copy to host:
```bash
scp -P 2222 p1@localhost:/home/p1/2022CSZ123456-P2.tar.gz .
```

---

## Problem 3 (P3)
After you successfully exploit P3 (which creates `/opt/p3/solved`):
```bash
ctf-extract P3
```
Package submission:
```bash
tar -czf 2022CSZ123456-P3.tar.gz flag.txt key.txt
```
Copy to host:
```bash
scp -P 2222 p1@localhost:/home/p1/2022CSZ123456-P3.tar.gz .
```

---

## Problem 4 (P4)
After you successfully exploit P4 (which creates `/opt/p4/solved`):
```bash
ctf-extract P4
```
Package submission:
```bash
tar -czf 2022CSZ123456-P4.tar.gz flag.txt key.txt
```
Copy to host:
```bash
scp -P 2222 p1@localhost:/home/p1/2022CSZ123456-P4.tar.gz .
```

---

## Problem 5 (P5)
After you submit CSS for P5 (which creates `/opt/p5/solved`):
```bash
ctf-extract P5
```
Package submission:
```bash
tar -czf 2022CSZ123456-P5.tar.gz flag.txt key.txt
```
Copy to host:
```bash
scp -P 2222 p1@localhost:/home/p1/2022CSZ123456-P5.tar.gz .
```
