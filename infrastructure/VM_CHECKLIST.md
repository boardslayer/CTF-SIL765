# VM Creation + Base Install Checklist (NSS A2)

Use this checklist to create the VM and prepare it for the P1 provisioning step.

## 1) Create the VM (VirtualBox)
- [x] Create new VM `NSS-A2-CTF`
- [x] Type: Linux, Version: Ubuntu (64-bit)
- [x] RAM: 2-4 GB
- [x] CPU: 2 cores
- [x] Disk: 20 GB (VDI, dynamic)

## 2) Configure Network
- [x] Adapter 1: NAT
- [x] Port forwards:
- [x] Host 2222 -> Guest 22 (SSH)
- [x] Host 8000 -> Guest 80 (HTTP)
- [x] Host 5901 -> Guest 5901 (VNC for P5)
- [x] Optional decoy forwards:
- [x] Host 9001 -> Guest 9001
- [x] Host 9002 -> Guest 9002

## 3) Attach ISO and Install OS
- [x] Attach `ubuntu-22.04.5-live-server-arm64.iso`
- [x] Install Ubuntu Server 22.04
- [x] Create user `ctfadmin`, password `thisisastrongpassword`
- [x] Enable OpenSSH server
- [x] Complete install and reboot

## 4) Base Package Install (inside VM)
Run (skip `apt update/upgrade` if you want to avoid updating existing software):
```bash
sudo apt update
sudo apt -y upgrade
sudo apt -y install openssh-server nginx build-essential gdb python3 python3-pip net-tools socat
```

## 5) Copy Provision Script into VM
- [ ] Copy `p1/provision_p1.sh` into VM (e.g., via `scp` or shared folder)

Example from host:
```bash
scp -P 2222 p1/provision_p1.sh ctfadmin@localhost:/home/ctfadmin/
```

## 6) Run P1 Provisioning Script
Inside VM:
```bash
sudo bash /home/ctfadmin/provision_p1.sh
```

## 7) Quick Verification
From host:
```bash
curl http://localhost:8000/backup/id_rsa
```
Inside VM:
```bash
sudo systemctl status nginx
sudo systemctl status ssh
```

---

When complete, tell me and we'll move on to P2-P4 setup.

P5 notes:
- VNC server runs on `:1` (host port 5901)
- P5 web app runs on `http://127.0.0.1:5005` inside the VM
