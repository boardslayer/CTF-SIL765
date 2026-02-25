# NSS A2 — CTF Assignment (SIL765 / COL7165)

This repository accompanies the CTF assignment for **Networks & System Security (SIL765 / COL7165)**.

It is organised into three sections:

| Directory | Contents |
|-----------|----------|
| [`assignment/`](assignment/README.md) | The original student-facing assignment — five problems covering SSH key leakage, SUID privilege escalation, stack buffer overflows, a format-string vulnerability, and CSS hijacking. |
| [`infrastructure/`](infrastructure/README.md) | How the assignment VM was constructed — the full build guide, Vagrant automation, and per-problem provisioning scripts with the vulnerable C source code. |
| [`solutions/`](solutions/README.md) | Complete walkthrough for every problem (AArch64 and x86_64 variants), standalone exploit scripts for P3 and P4, and grading scripts used to verify submissions. |

---

## Quick Navigation

### Assignment
- [Problem statement](assignment/README.md)

### Build (How It Was Made)
- [VM build guide](infrastructure/README.md)
- [VM creation checklist](infrastructure/VM_CHECKLIST.md)
- [Vagrant automation](infrastructure/Vagrantfile)
- Provisioning scripts: [P1](infrastructure/provision/p1/provision_p1.sh) · [P2](infrastructure/provision/p2/provision_p2.sh) · [P3](infrastructure/provision/p3/provision_p3.sh) · [P4](infrastructure/provision/p4/provision_p4.sh) · [P5](infrastructure/provision/p5/provision_p5.sh)
- Vulnerable source: [p2.c](infrastructure/provision/p2/p2.c) · [p3.c](infrastructure/provision/p3/p3.c) · [p4.c](infrastructure/provision/p4/p4.c)

### Solutions
- [Full walkthrough — AArch64](solutions/README.md)
- [Full walkthrough — x86_64](solutions/README_x86.md)
- [Flag extraction commands](solutions/FLAG_EXTRACTION.md)
- Exploit scripts: [P3 ret2win](solutions/p3_exploit.py) · [P4 format-string](solutions/p4_exploit.py)
- Grading scripts: [P1](solutions/grading/verify_p1.py) · [P3](solutions/grading/verify_p3.py) · [P4](solutions/grading/verify_p4.py) · [P5](solutions/grading/verify_p5.py)

---

## Problem Overview

| # | Title | Technique |
|---|-------|-----------|
| P1 | Gain Access | Information leakage → SSH key recovery |
| P2 | Become Super | SUID-root binary, stack buffer overflow → root shell |
| P3 | Changing the Flow | NX-enabled binary, ret2win (no shellcode) |
| P4 | Is 'In and Out' Safe? | Format-string vulnerability, `%n` write to flip auth check |
| P5 | CSS Hijacking | Attacker-controlled stylesheet reveals hidden flag |

Each problem builds on the previous: students must first gain unprivileged access (P1) before attempting the local exploitation problems (P2–P5).

