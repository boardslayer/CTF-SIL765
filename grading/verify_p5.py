#!/usr/bin/env python3
import argparse
import hashlib
import sys
from pathlib import Path


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def main() -> int:
    p = argparse.ArgumentParser(description="Verify NSS A2 P5 submission files")
    p.add_argument("--key", help="Path to boot.key used for this VM boot (optional if key.txt exists)")
    p.add_argument("--keytxt", default="key.txt", help="Path to key.txt (submission)")
    p.add_argument("--flag", default="flag.txt", help="Path to flag.txt")
    args = p.parse_args()

    key_path = Path(args.key) if args.key else Path(args.keytxt)
    if not key_path.exists():
        print("[FAIL] No key provided. Use --key or include key.txt in the submission.")
        return 2

    key = read_text(key_path)
    flag = read_text(Path(args.flag))

    exp_flag = sha256_hex(f"P5:{key}")

    if flag != exp_flag:
        print("[FAIL] flag.txt does not match expected value")
        print("[INFO] Expected flag:")
        print(exp_flag)
        return 1

    print("[OK] P5 submission verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
