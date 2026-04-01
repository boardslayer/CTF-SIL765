#!/usr/bin/env python3
"""
CTF Assignment 2 — Master Grading Script
Extracts, verifies, detects copying & gibberish across all student submissions.

Usage:
    python3 grade_all.py --submissions /path/to/student_solution --output grades.csv
"""

import argparse
import csv
import hashlib
import os
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROBLEMS = ["P1", "P2", "P3", "P4", "P5"]

# Map course label -> directory suffix under submissions root
COURSE_DIRS = {
    "SIL765": "2502-SIL765A-Assignment 2-156123",
    "COL7165": "2502-SIL7165A-Assignment 2-156121",
}

# Security limits
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB — flag.txt and key.txt should be < 1 KB
MAX_ARCHIVE_MEMBERS = 50  # No legitimate submission has > ~10 members
MAX_TOTAL_EXTRACT = 10 * 1024 * 1024  # 10 MB total extraction budget per archive
ALLOWED_FILENAMES = {"flag.txt", "key.txt"}

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------


class SecurityViolation(Exception):
    """Raised when a submission archive contains something suspicious."""

    pass


def _is_path_safe(member_name: str, dest: Path) -> bool:
    """Check that an archive member extracts strictly inside *dest*."""
    # Resolve the full target path
    target = (dest / member_name).resolve()
    # Must be under dest
    try:
        target.relative_to(dest.resolve())
        return True
    except ValueError:
        return False


def _check_tar_member(member: tarfile.TarInfo, dest: Path) -> list[str]:
    """
    Validate a single tar member. Returns list of warnings (empty = safe).
    Raises SecurityViolation for serious issues.
    """
    warnings = []

    # 1. Path traversal
    if not _is_path_safe(member.name, dest):
        raise SecurityViolation(
            f"Path traversal detected: '{member.name}' escapes extraction dir"
        )

    # 2. Absolute paths
    if member.name.startswith("/") or member.name.startswith("\\"):
        raise SecurityViolation(f"Absolute path in archive: '{member.name}'")

    # 3. Symlinks / hardlinks
    if member.issym() or member.islnk():
        raise SecurityViolation(
            f"Symlink/hardlink in archive: '{member.name}' -> '{member.linkname}'"
        )

    # 4. Device files, FIFOs, etc.
    if not (member.isfile() or member.isdir()):
        raise SecurityViolation(
            f"Non-regular file type in archive: '{member.name}' (type={member.type})"
        )

    # 5. Oversized files
    if member.isfile() and member.size > MAX_FILE_SIZE:
        raise SecurityViolation(
            f"Oversized file: '{member.name}' is {member.size} bytes "
            f"(limit {MAX_FILE_SIZE})"
        )

    # 6. Suspicious filenames (not flag.txt / key.txt / directories)
    basename = os.path.basename(member.name)
    if member.isfile() and basename not in ALLOWED_FILENAMES:
        warnings.append(f"Unexpected file in archive: '{member.name}'")

    return warnings


def _check_zip_member(info: zipfile.ZipInfo, dest: Path) -> list[str]:
    """Validate a single zip member. Returns warnings; raises on violations."""
    warnings = []

    # Path traversal
    if not _is_path_safe(info.filename, dest):
        raise SecurityViolation(f"Path traversal in zip: '{info.filename}'")

    # Absolute paths
    if info.filename.startswith("/") or info.filename.startswith("\\"):
        raise SecurityViolation(f"Absolute path in zip: '{info.filename}'")

    # Zip bomb: check compression ratio
    if info.file_size > MAX_FILE_SIZE and not info.filename.endswith("/"):
        raise SecurityViolation(
            f"Oversized file in zip: '{info.filename}' is {info.file_size} bytes"
        )

    # Symlinks in zip (rare but possible via external_attr)
    # Unix symlink: (external_attr >> 16) & 0o170000 == 0o120000
    unix_mode = (info.external_attr >> 16) & 0o170000
    if unix_mode == 0o120000:
        raise SecurityViolation(f"Symlink in zip: '{info.filename}'")

    return warnings


def safe_extract_tar(archive_path: Path, dest: Path) -> list[str]:
    """
    Safely extract a tar archive into *dest*.
    Tries r:gz first, then r:bz2, then r: (plain tar) as fallback.
    Returns list of security warnings. Raises SecurityViolation on bad archives.
    """
    # Try multiple tar modes — students often name plain tars as .tar.gz
    last_err = None
    for mode in ("r:gz", "r:bz2", "r:xz", "r:"):
        try:
            return _do_safe_extract_tar(archive_path, dest, mode)
        except (tarfile.TarError, OSError, EOFError) as e:
            last_err = e
            continue
    raise last_err or tarfile.TarError(f"Cannot open '{archive_path.name}' as tar")


def _do_safe_extract_tar(
    archive_path: Path, dest: Path, mode: str
) -> list[str]:
    """Inner extraction with a specific tar mode."""
    all_warnings = []
    total_size = 0

    with tarfile.open(str(archive_path), mode) as tf:
        members = tf.getmembers()

        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise SecurityViolation(
                f"Too many members ({len(members)}) in '{archive_path.name}'"
            )

        # Pre-scan all members before extracting anything
        for m in members:
            all_warnings.extend(_check_tar_member(m, dest))
            if m.isfile():
                total_size += m.size

        if total_size > MAX_TOTAL_EXTRACT:
            raise SecurityViolation(
                f"Total extracted size {total_size} exceeds limit "
                f"{MAX_TOTAL_EXTRACT} for '{archive_path.name}'"
            )

        # Safe to extract — only regular files and dirs
        safe_members = [m for m in members if m.isfile() or m.isdir()]
        tf.extractall(dest, members=safe_members)

    return all_warnings


def safe_extract_zip(zip_path: Path, dest: Path) -> list[str]:
    """
    Safely extract a zip archive into *dest*.
    Returns list of security warnings. Raises SecurityViolation on bad archives.
    """
    all_warnings = []
    total_size = 0

    with zipfile.ZipFile(str(zip_path), "r") as zf:
        members = zf.infolist()

        if len(members) > MAX_ARCHIVE_MEMBERS * 10:  # zips may contain nested tars
            raise SecurityViolation(
                f"Too many members ({len(members)}) in '{zip_path.name}'"
            )

        for info in members:
            # Skip __MACOSX resource forks
            if "__MACOSX" in info.filename:
                continue
            all_warnings.extend(_check_zip_member(info, dest))
            if not info.filename.endswith("/"):
                total_size += info.file_size

        if total_size > MAX_TOTAL_EXTRACT:
            raise SecurityViolation(
                f"Total extracted size {total_size} exceeds limit for '{zip_path.name}'"
            )

        # Extract, skipping __MACOSX
        for info in members:
            if "__MACOSX" in info.filename:
                continue
            zf.extract(info, dest)

    return all_warnings


def validate_file_content(path: Path, label: str) -> list[str]:
    """
    Check that an extracted text file doesn't contain anything dangerous.
    Returns list of warnings.
    """
    warnings = []
    if not path.exists():
        return warnings

    # Binary content check — flag.txt and key.txt should be pure text
    try:
        content = path.read_bytes()
    except OSError:
        warnings.append(f"Cannot read {label}: {path}")
        return warnings

    # Check for null bytes (binary content)
    if b"\x00" in content:
        warnings.append(
            f"{label} contains null bytes — possible binary/malicious content"
        )

    # Check for shell injection patterns in text content
    text = content.decode("utf-8", errors="replace").strip()
    shell_patterns = [
        r";\s*(rm|wget|curl|bash|sh|python|nc|exec|eval)\b",
        r"\$\(",  # command substitution
        r"`[^`]+`",  # backtick execution
        r"\|\s*(bash|sh)",  # pipe to shell
        r">\s*/",  # redirect to absolute path
    ]
    for pat in shell_patterns:
        if re.search(pat, text, re.IGNORECASE):
            warnings.append(
                f"{label} contains suspicious shell pattern matching '{pat}'"
            )

    # Excessive size for what should be a short string
    if len(content) > 4096:
        warnings.append(f"{label} is suspiciously large: {len(content)} bytes")

    return warnings


# ---------------------------------------------------------------------------
# Crypto verification
# ---------------------------------------------------------------------------


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def verify_problem(
    problem_dir: Path | None, problem: str
) -> tuple[str, str, str, list[str]]:
    """
    Verify a single problem submission.
    Returns (status, flag_value, key_value, warnings).
    """
    if problem_dir is None:
        return ("MISSING", "", "", [])

    flag_path = find_file(problem_dir, "flag.txt")
    key_path = find_file(problem_dir, "key.txt")

    if flag_path is None and key_path is None:
        return ("MISSING", "", "", [])

    warnings = []

    # Validate file contents for safety
    if flag_path:
        warnings.extend(validate_file_content(flag_path, "flag.txt"))
    if key_path:
        warnings.extend(validate_file_content(key_path, "key.txt"))

    flag = (
        flag_path.read_text("utf-8").strip() if flag_path and flag_path.exists() else ""
    )
    key = key_path.read_text("utf-8").strip() if key_path and key_path.exists() else ""

    # Both empty
    if not flag and not key:
        return ("EMPTY", flag, key, warnings)

    # Flag present but no key — cannot verify
    if flag and not key:
        return ("GIBBERISH", flag, key, warnings)

    # Key present but no flag
    if not flag and key:
        return ("EMPTY", flag, key, warnings)

    # Flag doesn't look like valid SHA256 hex
    if not re.fullmatch(r"[0-9a-fA-F]{64}", flag):
        return ("GIBBERISH", flag, key, warnings)

    # Both present — verify
    expected = sha256_hex(f"{problem}:{key}")
    if flag.lower() == expected.lower():
        return ("PASS", flag, key, warnings)
    else:
        return ("FAIL", flag, key, warnings)


def find_file(base_dir: Path, filename: str) -> Path | None:
    """
    Find a file by name inside base_dir, searching up to 2 levels deep.
    Returns the first match or None.
    """
    # Direct child
    direct = base_dir / filename
    if direct.exists():
        return direct

    # Search one level of subdirectories (some tarballs nest in a folder)
    for child in base_dir.iterdir():
        if child.is_dir():
            candidate = child / filename
            if candidate.exists():
                return candidate

    return None


# ---------------------------------------------------------------------------
# Archive extraction & student discovery
# ---------------------------------------------------------------------------


def identify_problem(filename: str) -> str | None:
    """Extract problem identifier (P1-P5) from a filename."""
    m = re.search(r"[_\-]?(P[1-5])", filename, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    return None


def extract_entry_number(student_folder: Path) -> str:
    """Extract student entry number from archive filenames."""
    for f in sorted(student_folder.iterdir()):
        if f.name.startswith("."):
            continue
        m = re.match(r"^(\d{4}[A-Za-z]{2,4}\d{4,5})", f.name)
        if m:
            return m.group(1)
    return "UNKNOWN"


def parse_student_name(folder_name: str) -> str:
    """Extract human name from Moodle folder name."""
    # Format: "Full Name_1234567_assignsubmission_file_"
    parts = folder_name.split("_")
    if len(parts) >= 2:
        return parts[0].strip()
    return folder_name


def extract_submissions(
    student_folder: Path, tmpdir: Path
) -> tuple[dict, list[str], dict]:
    """
    Extract all problem archives for a student.
    Returns (problem_dirs, warnings, tar_metadata).
    tar_metadata: {problem: {"unames": set, "gnames": set, "mtimes": list}}
    """
    results = {}
    all_warnings = []
    tar_meta = {}

    # Collect both files and directories (bare directory submissions)
    entries = sorted(
        f for f in student_folder.iterdir()
        if not f.name.startswith(".")
    )
    files = [f for f in entries if f.is_file()]
    dirs = [d for d in entries if d.is_dir()]

    if not files and not dirs:
        return results, ["No files found in submission folder"], tar_meta

    # Detect format: single zip vs multiple per-problem archives
    is_single_zip = len(files) == 1 and not dirs and (
        files[0].suffix == ".zip" or files[0].name.endswith(".tar.zip")
    )

    if is_single_zip:
        all_warnings.extend(
            _extract_zip_then_tarballs(files[0], tmpdir, results, tar_meta)
        )
    else:
        # Handle archive files
        for f in files:
            problem = identify_problem(f.name)
            if problem is None:
                all_warnings.append(f"Cannot identify problem for file: {f.name}")
                continue
            # Skip if we already extracted this problem from a tar (avoid
            # processing both a directory and a .tar.gz for the same problem)
            if problem in results and results[problem] is not None:
                continue
            warnings = _extract_single_archive(f, tmpdir, problem, results, tar_meta)
            all_warnings.extend(warnings)

        # Handle bare directories (student uploaded a directory instead of tar)
        for d in dirs:
            problem = identify_problem(d.name)
            if problem is None:
                continue
            # Skip if already extracted from a tarball
            if problem in results and results[problem] is not None:
                continue
            warnings = _copy_bare_directory(d, tmpdir, problem, results)
            all_warnings.extend(warnings)

    return results, all_warnings, tar_meta


def _extract_single_archive(
    archive: Path, tmpdir: Path, problem: str, results: dict,
    tar_meta: dict
) -> list[str]:
    """Extract a single tar archive (any compression). Returns warnings."""
    dest = tmpdir / problem
    dest.mkdir(exist_ok=True)

    try:
        warnings = safe_extract_tar(archive, dest)
        results[problem] = dest

        # Capture tar metadata for fabrication detection.
        # Try all modes since the file might not be gzip.
        for mode in ("r:gz", "r:bz2", "r:xz", "r:"):
            try:
                with tarfile.open(str(archive), mode) as tf:
                    members = tf.getmembers()
                    tar_meta[problem] = {
                        "unames": set(m.uname for m in members if m.isfile()),
                        "gnames": set(m.gname for m in members if m.isfile()),
                        "mtimes": [m.mtime for m in members if m.isfile()],
                    }
                break
            except Exception:
                continue

        return warnings
    except (tarfile.TarError, SecurityViolation, OSError) as e:
        results[problem] = None
        return [f"Extraction error for {archive.name}: {e}"]


def _copy_bare_directory(
    src_dir: Path, tmpdir: Path, problem: str, results: dict
) -> list[str]:
    """Handle a bare directory submission (not archived). Copy it to tmpdir."""
    import shutil

    warnings = [f"Bare directory submission for {problem} (not archived)"]
    dest = tmpdir / problem
    dest.mkdir(exist_ok=True)

    total_size = 0
    file_count = 0
    for f in src_dir.rglob("*"):
        if f.name.startswith("."):
            continue
        if f.is_file():
            file_count += 1
            total_size += f.stat().st_size
            if file_count > MAX_ARCHIVE_MEMBERS:
                warnings.append(f"Too many files in bare directory: {src_dir.name}")
                results[problem] = None
                return warnings
            if total_size > MAX_TOTAL_EXTRACT:
                warnings.append(f"Directory too large: {src_dir.name}")
                results[problem] = None
                return warnings

            # Security: check for path traversal
            rel = f.relative_to(src_dir)
            target = dest / rel
            if ".." in rel.parts:
                warnings.append(f"Skipping suspicious path: {rel}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, target)

    results[problem] = dest
    return warnings


def _extract_zip_then_tarballs(
    zip_path: Path, tmpdir: Path, results: dict, tar_meta: dict
) -> list[str]:
    """Extract a zip, then extract each tarball found inside."""
    zip_dir = tmpdir / "_zip_contents"
    zip_dir.mkdir(exist_ok=True)
    all_warnings = []

    try:
        all_warnings.extend(safe_extract_zip(zip_path, zip_dir))
    except (zipfile.BadZipFile, SecurityViolation) as e:
        all_warnings.append(f"Zip extraction error for {zip_path.name}: {e}")
        return all_warnings

    # Find tarballs inside the extracted zip
    for f in sorted(zip_dir.rglob("*")):
        if "__MACOSX" in f.parts:
            continue
        if not f.is_file():
            continue

        problem = identify_problem(f.name)
        if problem is None:
            continue

        # Check if this is a tarball (even if extension is weird)
        if (
            f.suffix in (".gz", ".tgz")
            or f.name.endswith(".tar.gz")
            or f.name.endswith(".tag.gz")
        ):
            warnings = _extract_single_archive(f, tmpdir, problem, results, tar_meta)
            all_warnings.extend(warnings)

    return all_warnings


# ---------------------------------------------------------------------------
# Cheating detection — multi-layer analysis
# ---------------------------------------------------------------------------


def _build_key_index(all_students: list[dict]) -> dict[str, list[tuple[str, str]]]:
    """
    Build a global index: key_value -> [(entry, problem), ...].
    This powers most cheating checks.
    """
    idx = defaultdict(list)
    for s in all_students:
        for p in PROBLEMS:
            key = s[p]["key"]
            if key:
                idx[key].append((s["entry"], p))
    return idx


def _build_flag_index(all_students: list[dict]) -> dict[str, list[tuple[str, str]]]:
    """
    Build global index: flag_value -> [(entry, problem), ...].
    """
    idx = defaultdict(list)
    for s in all_students:
        for p in PROBLEMS:
            flag = s[p]["flag"]
            if flag:
                idx[flag].append((s["entry"], p))
    return idx


def _build_student_map(all_students: list[dict]) -> dict[str, dict]:
    """entry -> student dict for O(1) lookups."""
    return {s["entry"]: s for s in all_students}


# --- Layer 1: Per-problem key sharing (basic) ---

def detect_same_key_per_problem(all_students: list[dict]) -> None:
    """If two+ students have the same key.txt for the same problem, flag it."""
    for problem in PROBLEMS:
        key_to_entries = defaultdict(list)
        for s in all_students:
            key = s[problem]["key"]
            if key:
                key_to_entries[key].append(s["entry"])

        group_counter = 0
        for key_val, entries in key_to_entries.items():
            if len(entries) >= 2:
                group_counter += 1
                group_id = f"{problem}_COPY_{group_counter}"
                for s in all_students:
                    if s[problem]["key"] == key_val:
                        s[problem]["copy_group"] = group_id


# --- Layer 2: Cross-problem key clustering (graph-based) ---

def detect_key_clusters(all_students: list[dict]) -> None:
    """
    Build an undirected graph: students are nodes, edges connect students
    who share ANY key across ANY problem. Connected components = cheating
    clusters. This catches transitive copying (A->B, B->C means A,B,C
    are all in one cluster).
    """
    key_idx = _build_key_index(all_students)
    smap = _build_student_map(all_students)

    # Build adjacency: entry -> set of entries sharing a key
    adj = defaultdict(set)
    for key_val, users in key_idx.items():
        entries = set(e for e, _ in users)
        if len(entries) >= 2:
            for e in entries:
                adj[e].update(entries - {e})

    # BFS to find connected components
    visited = set()
    cluster_id = 0

    for s in all_students:
        entry = s["entry"]
        if entry in visited or entry not in adj:
            continue

        # BFS from this node
        cluster_id += 1
        component = []
        queue = [entry]
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            component.append(node)
            for neighbor in adj[node]:
                if neighbor not in visited:
                    queue.append(neighbor)

        if len(component) < 2:
            continue

        cluster_label = f"CLUSTER_{cluster_id}"
        members_str = ", ".join(sorted(component))

        # Figure out which specific problems are shared within the cluster
        shared_problems = []
        for p in PROBLEMS:
            p_keys = defaultdict(list)
            for e in component:
                k = smap[e][p]["key"]
                if k:
                    p_keys[k].append(e)
            for k, elist in p_keys.items():
                if len(elist) >= 2:
                    shared_problems.append(f"{p}({len(elist)} students)")

        for e in component:
            others = sorted(set(component) - {e})
            smap[e]["notes"].append(
                f"{cluster_label}: shared keys with {', '.join(others)} "
                f"[{', '.join(shared_problems)}]"
            )


# --- Layer 3: Flag-value coincidence ---

def detect_flag_collisions(all_students: list[dict]) -> None:
    """
    If two students have the exact same flag for the same problem but
    DIFFERENT keys, someone literally copied the flag.txt file without
    re-extracting (or fabricated it). SHA256 has no practical collisions,
    so same flag + different key = copied flag.
    """
    for p in PROBLEMS:
        flag_to_entries = defaultdict(list)
        for s in all_students:
            flag = s[p]["flag"]
            if flag and s[p]["status"] in ("PASS", "FAIL"):
                flag_to_entries[flag].append(s)

        for flag_val, students in flag_to_entries.items():
            if len(students) < 2:
                continue

            # Check if they also share the key (already caught by Layer 1)
            keys = set(s[p]["key"] for s in students)
            if len(keys) == 1:
                continue  # Same key = same flag is expected, already flagged

            # Different keys but same flag — this is impossible legitimately
            entries = [s["entry"] for s in students]
            for s in students:
                s["notes"].append(
                    f"SUSPICIOUS: {p} flag identical to {', '.join(e for e in entries if e != s['entry'])} "
                    f"but keys differ — flag was likely copied directly"
                )


# --- Layer 4: Cross-problem key consistency ---

def detect_key_inconsistency(all_students: list[dict]) -> None:
    """
    A student working on one VM session should have the SAME key for all
    problems they solved (since boot.key is shared). If they have DIFFERENT
    keys across problems, they either:
      (a) rebooted between problems (legitimate but unusual), OR
      (b) copied individual problems from different sources (suspicious).

    We flag case (b) by checking if ANY of their keys match other students.
    """
    key_idx = _build_key_index(all_students)

    for s in all_students:
        keys_used = {}
        for p in PROBLEMS:
            k = s[p]["key"]
            if k:
                keys_used[p] = k

        unique_keys = set(keys_used.values())
        if len(unique_keys) <= 1:
            continue  # All same key or at most 1 submission — fine

        # Multiple different keys. Check if any belong to other students.
        sourced_from = defaultdict(set)  # other_entry -> set of problems
        for p, k in keys_used.items():
            for other_entry, other_p in key_idx[k]:
                if other_entry != s["entry"]:
                    sourced_from[other_entry].add(p)

        if sourced_from:
            parts = []
            for other, probs in sorted(sourced_from.items()):
                parts.append(f"{', '.join(sorted(probs))} from {other}")
            s["notes"].append(
                f"MULTI-SOURCE: used {len(unique_keys)} different keys — "
                f"appears to have copied {'; '.join(parts)}"
            )
        else:
            # Different keys but none match anyone else — likely just rebooted
            s["notes"].append(
                f"INFO: used {len(unique_keys)} different boot keys across "
                f"problems (rebooted VM between problems)"
            )


# --- Layer 5: Cross-course copying ---

def detect_cross_course(all_students: list[dict]) -> None:
    """
    Flag when a SIL765 student and a COL7165 student share a key.
    This is especially suspicious since they're in different sections.
    """
    key_idx = _build_key_index(all_students)
    smap = _build_student_map(all_students)

    already_noted = set()  # avoid duplicate notes per pair

    for key_val, users in key_idx.items():
        entries = [(e, p) for e, p in users]
        courses = set(smap[e]["course"] for e, _ in entries)

        if len(courses) < 2:
            continue  # same course — already handled by other layers

        pair_key = frozenset(e for e, _ in entries)
        if pair_key in already_noted:
            continue
        already_noted.add(pair_key)

        by_course = defaultdict(list)
        for e, p in entries:
            by_course[smap[e]["course"]].append(e)

        course_parts = [
            f"{c}: {', '.join(sorted(set(es)))}"
            for c, es in sorted(by_course.items())
        ]

        for e, p in entries:
            smap[e]["notes"].append(
                f"CROSS-COURSE copying detected [{'; '.join(course_parts)}]"
            )


# --- Layer 6: Flag-swap / wrong-problem detection ---

def detect_flag_swaps(all_students: list[dict]) -> None:
    """
    Check if a student's flag for problem X actually corresponds to a
    DIFFERENT problem number with their key. e.g., they submitted P3's
    flag in P2's slot. This catches careless copiers.
    """
    for s in all_students:
        for p in PROBLEMS:
            flag = s[p]["flag"]
            key = s[p]["key"]
            if not flag or not key or s[p]["status"] != "FAIL":
                continue  # only check FAILed submissions

            # Does this flag match a different problem with the same key?
            for other_p in PROBLEMS:
                if other_p == p:
                    continue
                expected_other = sha256_hex(f"{other_p}:{key}")
                if flag.lower() == expected_other.lower():
                    s["notes"].append(
                        f"FLAG-SWAP: {p} flag.txt actually contains the "
                        f"flag for {other_p} (wrong problem slot)"
                    )
                    break

            # Does this flag match ANY other student's valid flag for this problem?
            # (i.e., flag is correct for someone else's key)
            # Already partially covered by Layer 3, but let's be explicit
            # about "this is literally another student's flag"


# --- Layer 7: Bulk-identical submissions (archive-level) ---

def detect_submission_clones(all_students: list[dict]) -> None:
    """
    If two students have the exact same (flag, key) pair for 3+ problems,
    they almost certainly shared the entire VM session output. This catches
    cases where per-problem detection might miss the big picture.
    """
    # Build fingerprint: tuple of (flag, key) across all problems
    def fingerprint(s):
        return tuple(
            (s[p]["flag"], s[p]["key"])
            for p in PROBLEMS
            if s[p]["flag"] or s[p]["key"]
        )

    fp_to_students = defaultdict(list)
    for s in all_students:
        fp = fingerprint(s)
        if len(fp) >= 3:  # need at least 3 non-empty submissions
            fp_to_students[fp].append(s["entry"])

    for fp, entries in fp_to_students.items():
        if len(entries) < 2:
            continue
        for s in all_students:
            if s["entry"] in entries:
                others = [e for e in entries if e != s["entry"]]
                s["notes"].append(
                    f"CLONE: submission fingerprint identical to "
                    f"{', '.join(sorted(others))} across {len(fp)} problems"
                )


# --- Layer 8: Fabrication detection via tar metadata ---

# Usernames that belong to the VM (legitimate archive creators)
VM_USERNAMES = {"p1", "root", "p3flag", "p4flag", "ctfadmin", "vagrant"}


def detect_fabrication(all_students: list[dict]) -> None:
    """
    Use tar archive metadata to detect likely fabricated submissions.

    Real submissions are created ON the VM → tar uname is 'p1' or 'root'.
    Fabricated submissions are created on a personal machine → tar uname
    is a personal username like 'abhi', 'apple', 'bansal', etc.

    A personal uname isn't proof of fabrication (student may have SCP'd files
    then tarred locally), but combined with 5/5 PASS and no shared keys,
    it raises the suspicion level significantly.
    """
    for s in all_students:
        tar_meta = s.get("tar_meta", {})
        if not tar_meta:
            continue

        personal_unames = set()
        vm_unames = set()
        problems_from_vm = []
        problems_from_personal = []

        for p in PROBLEMS:
            meta = tar_meta.get(p)
            if not meta:
                continue
            unames = meta.get("unames", set())
            for u in unames:
                if u in VM_USERNAMES:
                    vm_unames.add(u)
                    problems_from_vm.append(p)
                elif u:
                    personal_unames.add(u)
                    problems_from_personal.append(p)

        s["tar_unames_vm"] = vm_unames
        s["tar_unames_personal"] = personal_unames

        if personal_unames and not vm_unames:
            # ALL archives created on personal machine — high fabrication risk
            s["notes"].append(
                f"FABRICATION-RISK-HIGH: all archives created by "
                f"'{', '.join(sorted(personal_unames))}' (personal machine), "
                f"not on the VM (expected 'p1' or 'root')"
            )
        elif personal_unames and vm_unames:
            # Mix of VM and personal — some problems may be fabricated
            s["notes"].append(
                f"FABRICATION-RISK-MIXED: {', '.join(problems_from_personal)} "
                f"created by '{', '.join(sorted(personal_unames))}' (personal), "
                f"{', '.join(problems_from_vm)} created on VM"
            )


# --- Layer 9: Suspicion score ---

def compute_suspicion_scores(all_students: list[dict]) -> None:
    """
    Compute an overall suspicion score (0-100) for each student based on
    all available signals. This helps prioritize who to investigate.
    """
    for s in all_students:
        score = 0
        reasons = []

        # Archives created on personal machine (not VM)
        if s.get("tar_unames_personal") and not s.get("tar_unames_vm"):
            score += 40
            reasons.append(f"all archives from personal machine (+40)")
        elif s.get("tar_unames_personal"):
            score += 15
            reasons.append("some archives from personal machine (+15)")

        # Copy group membership
        for p in PROBLEMS:
            if s[p]["copy_group"]:
                score += 20
                reasons.append(f"{p} shared key (+20)")

        # Multi-source keys (copied from different people)
        for n in s["notes"]:
            if "MULTI-SOURCE" in n:
                score += 30
                reasons.append("multi-source keys (+30)")
                break

        # Cross-course copying
        for n in s["notes"]:
            if "CROSS-COURSE" in n:
                score += 25
                reasons.append("cross-course key sharing (+25)")
                break

        # Clone detection
        for n in s["notes"]:
            if "CLONE" in n:
                score += 35
                reasons.append("submission clone (+35)")
                break

        # Flag swap (careless error typical of copiers)
        for n in s["notes"]:
            if "FLAG-SWAP" in n:
                score += 15
                reasons.append("flag swap (+15)")
                break

        s["suspicion_score"] = min(score, 100)
        s["suspicion_reasons"] = reasons


# --- Orchestrator ---

def run_all_cheating_checks(all_students: list[dict]) -> None:
    """Run all cheating detection layers in order."""
    detect_same_key_per_problem(all_students)   # Layer 1: basic per-problem
    detect_key_clusters(all_students)            # Layer 2: graph clustering
    detect_flag_collisions(all_students)         # Layer 3: same flag diff key
    detect_key_inconsistency(all_students)       # Layer 4: multi-source keys
    detect_cross_course(all_students)            # Layer 5: cross-section
    detect_flag_swaps(all_students)              # Layer 6: wrong problem slot
    detect_submission_clones(all_students)        # Layer 7: bulk clones
    detect_fabrication(all_students)              # Layer 8: tar metadata
    compute_suspicion_scores(all_students)        # Layer 9: aggregate score


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "Name",
    "EntryNumber",
    "Course",
    "P1",
    "P2",
    "P3",
    "P4",
    "P5",
    "P1_CopyGroup",
    "P2_CopyGroup",
    "P3_CopyGroup",
    "P4_CopyGroup",
    "P5_CopyGroup",
    "TotalPassed",
    "SuspicionScore",
    "SuspicionReasons",
    "TarCreator",
    "SecurityWarnings",
    "Notes",
]


def write_csv(all_students: list[dict], output_path: Path) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for s in all_students:
            total_passed = sum(1 for p in PROBLEMS if s[p]["status"] == "PASS")

            # Tar creator summary
            vm_u = s.get("tar_unames_vm", set())
            personal_u = s.get("tar_unames_personal", set())
            tar_parts = []
            if vm_u:
                tar_parts.append(f"VM:{','.join(sorted(vm_u))}")
            if personal_u:
                tar_parts.append(f"PERSONAL:{','.join(sorted(personal_u))}")
            tar_creator = "; ".join(tar_parts)

            row = {
                "Name": s["name"],
                "EntryNumber": s["entry"],
                "Course": s["course"],
                "TotalPassed": total_passed,
                "SuspicionScore": s.get("suspicion_score", 0),
                "SuspicionReasons": "; ".join(s.get("suspicion_reasons", [])),
                "TarCreator": tar_creator,
                "SecurityWarnings": "; ".join(s.get("security_warnings", [])),
                "Notes": "; ".join(s["notes"]),
            }
            for p in PROBLEMS:
                row[p] = s[p]["status"]
                row[f"{p}_CopyGroup"] = s[p]["copy_group"]

            writer.writerow(row)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def print_summary(all_students: list[dict]) -> None:
    total = len(all_students)
    print(f"\n{'=' * 60}")
    print(f"GRADING SUMMARY — {total} students")
    print(f"{'=' * 60}")

    # --- Per-problem status counts ---
    print("\n--- Per-Problem Results ---")
    for p in PROBLEMS:
        counts = defaultdict(int)
        for s in all_students:
            counts[s[p]["status"]] += 1
        parts = [f"{status}: {count}" for status, count in sorted(counts.items())]
        print(f"  {p}: {', '.join(parts)}")

    # --- Copy groups (per-problem key sharing) ---
    print(f"\n--- Layer 1: Per-Problem Key Sharing ---")
    any_copies = False
    for p in PROBLEMS:
        groups = defaultdict(list)
        for s in all_students:
            grp = s[p]["copy_group"]
            if grp:
                groups[grp].append(f"{s['entry']} ({s['name']})")
        for grp, members in sorted(groups.items()):
            any_copies = True
            print(f"  {grp}: {', '.join(members)}")
    if not any_copies:
        print("  None detected.")

    # --- Cheating clusters ---
    print(f"\n--- Layer 2: Cheating Clusters (transitive key sharing) ---")
    cluster_notes = [
        (s["entry"], s["name"], n)
        for s in all_students
        for n in s["notes"]
        if n.startswith("CLUSTER_")
    ]
    if cluster_notes:
        seen_clusters = set()
        for entry, name, note in cluster_notes:
            cluster_id = note.split(":")[0]
            if cluster_id not in seen_clusters:
                seen_clusters.add(cluster_id)
                print(f"  {note}")
    else:
        print("  None detected.")

    # --- Cross-course ---
    print(f"\n--- Layer 5: Cross-Course Copying ---")
    cross = [
        (s["entry"], s["name"], n)
        for s in all_students
        for n in s["notes"]
        if "CROSS-COURSE" in n
    ]
    if cross:
        seen = set()
        for entry, name, note in cross:
            if note not in seen:
                seen.add(note)
                print(f"  {entry} ({name}): {note}")
    else:
        print("  None detected.")

    # --- Multi-source copying ---
    print(f"\n--- Layer 4: Multi-Source Copying ---")
    multi = [
        (s["entry"], s["name"], n)
        for s in all_students
        for n in s["notes"]
        if "MULTI-SOURCE" in n
    ]
    if multi:
        for entry, name, note in multi:
            print(f"  {entry} ({name}): {note}")
    else:
        print("  None detected.")

    # --- Flag swaps ---
    print(f"\n--- Layer 6: Flag Swaps (wrong problem slot) ---")
    swaps = [
        (s["entry"], s["name"], n)
        for s in all_students
        for n in s["notes"]
        if "FLAG-SWAP" in n
    ]
    if swaps:
        for entry, name, note in swaps:
            print(f"  {entry} ({name}): {note}")
    else:
        print("  None detected.")

    # --- Clones ---
    print(f"\n--- Layer 7: Submission Clones ---")
    clones = [
        (s["entry"], s["name"], n)
        for s in all_students
        for n in s["notes"]
        if "CLONE" in n
    ]
    if clones:
        for entry, name, note in clones:
            print(f"  {entry} ({name}): {note}")
    else:
        print("  None detected.")

    # --- Security warnings ---
    warned = [s for s in all_students if s.get("security_warnings")]
    if warned:
        print(f"\n--- Security Warnings ---")
        for s in warned:
            for w in s["security_warnings"]:
                print(f"  [{s['entry']}] {w}")

    # --- Gibberish ---
    gibberish = [
        (s["entry"], s["name"], p)
        for s in all_students
        for p in PROBLEMS
        if s[p]["status"] == "GIBBERISH"
    ]
    if gibberish:
        print(f"\n--- Gibberish Submissions ---")
        for entry, name, p in gibberish:
            print(f"  {entry} ({name}): {p}")

    # --- Layer 8: Fabrication analysis ---
    print(f"\n--- Layer 8: Archive Creator Analysis ---")
    print("  (VM = created on assignment VM as p1/root; PERSONAL = local machine)")
    fab_high = [s for s in all_students
                if any("FABRICATION-RISK-HIGH" in n for n in s["notes"])]
    fab_mixed = [s for s in all_students
                 if any("FABRICATION-RISK-MIXED" in n for n in s["notes"])]
    fab_vm = [s for s in all_students
              if s.get("tar_unames_vm") and not s.get("tar_unames_personal")]

    print(f"  Archives from VM only: {len(fab_vm)} students")
    print(f"  Archives from PERSONAL machine only: {len(fab_high)} students")
    print(f"  Mixed (some VM, some personal): {len(fab_mixed)} students")

    if fab_high:
        print(f"\n  HIGH fabrication risk (all archives from personal machine):")
        for s in sorted(fab_high, key=lambda x: x["entry"]):
            unames = ", ".join(sorted(s.get("tar_unames_personal", set())))
            tp = sum(1 for p in PROBLEMS if s[p]["status"] == "PASS")
            print(f"    {s['entry']} ({s['name']}): creator='{unames}', "
                  f"passed={tp}/5")

    # --- Overall suspicion ranking ---
    print(f"\n{'=' * 60}")
    print(f"SUSPICION RANKING (score > 0)")
    print(f"{'=' * 60}")

    ranked = sorted(
        [s for s in all_students if s.get("suspicion_score", 0) > 0],
        key=lambda s: -s["suspicion_score"]
    )

    if ranked:
        for s in ranked:
            score = s["suspicion_score"]
            bar = "#" * (score // 5)
            reasons = ", ".join(s.get("suspicion_reasons", []))
            print(f"  [{score:3d}] {bar:<20s} {s['entry']} ({s['name']}, {s['course']})")
            print(f"        {reasons}")
        print(f"\n  Scored > 0: {len(ranked)} / {total}")
        print(f"  Score >= 40: {sum(1 for s in ranked if s['suspicion_score'] >= 40)} students")
        print(f"  Score >= 20: {sum(1 for s in ranked if s['suspicion_score'] >= 20)} students")
    else:
        print("  No suspicion flags raised.")

    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Grade CTF Assignment 2 — verify flags, detect copying & gibberish"
    )
    parser.add_argument(
        "--submissions", required=True, help="Path to student_solution/ directory"
    )
    parser.add_argument(
        "--output", default="grades.csv", help="Output CSV path (default: grades.csv)"
    )
    args = parser.parse_args()

    submissions_root = Path(args.submissions)
    if not submissions_root.is_dir():
        print(f"ERROR: '{submissions_root}' is not a directory", file=sys.stderr)
        return 1

    all_students = []

    with tempfile.TemporaryDirectory(prefix="ctf_grade_") as tmp:
        tmpdir = Path(tmp)

        for course, dir_name in COURSE_DIRS.items():
            course_dir = submissions_root / dir_name
            if not course_dir.exists():
                print(f"WARNING: {course_dir} not found, skipping {course}")
                continue

            print(f"Processing {course} ({course_dir.name}) ...")

            for student_folder in sorted(course_dir.iterdir()):
                if not student_folder.is_dir():
                    continue
                if student_folder.name.startswith("."):
                    continue

                name = parse_student_name(student_folder.name)
                entry = extract_entry_number(student_folder)

                student_tmp = tmpdir / f"{course}_{entry}"
                student_tmp.mkdir(exist_ok=True)

                # Extract all archives
                problem_dirs, extraction_warnings, tar_meta = extract_submissions(
                    student_folder, student_tmp
                )

                # Build student record
                student = {
                    "name": name,
                    "entry": entry,
                    "course": course,
                    "notes": [],
                    "security_warnings": extraction_warnings,
                    "tar_meta": tar_meta,
                }

                if entry == "UNKNOWN":
                    student["notes"].append(
                        f"No entry number found in filenames (folder: {student_folder.name})"
                    )

                # Verify each problem
                for p in PROBLEMS:
                    status, flag, key, file_warnings = verify_problem(
                        problem_dirs.get(p), p
                    )
                    student["security_warnings"].extend(file_warnings)
                    student[p] = {
                        "status": status,
                        "flag": flag,
                        "key": key,
                        "copy_group": "",
                    }

                all_students.append(student)

        # Cheating detection — all 7 layers
        run_all_cheating_checks(all_students)

    # Sort by entry number
    all_students.sort(key=lambda s: s["entry"])

    # Output
    output_path = Path(args.output)
    write_csv(all_students, output_path)
    print(f"\nCSV written to: {output_path}")

    print_summary(all_students)

    return 0


if __name__ == "__main__":
    sys.exit(main())
