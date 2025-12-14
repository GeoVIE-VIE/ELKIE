#!/usr/bin/env python3
"""
Dump all extracted honeypot samples to a single text file for easy review.

Reads the samples.jsonl catalog and combines all sample contents into:
  - ~/honeypot_samples_combined.txt  (all samples concatenated)
  - ~/honeypot_samples_manifest.txt  (list of paths + stats)

Usage:
    python3 dump_honeypot_samples.py
    # or
    sudo python3 dump_honeypot_samples.py  # if samples need root to read
"""

import json
import os
import sys
from datetime import datetime

JSONL_PATH = "/var/log/honeypot-extraction/samples.jsonl"

OUT_TXT = os.path.expanduser("~/honeypot_samples_combined.txt")
OUT_MANIFEST = os.path.expanduser("~/honeypot_samples_manifest.txt")

# Prefer quarantine_path, fall back to original_path
PATH_KEYS = ("quarantine_path", "original_path")

def pick_path(obj: dict) -> str | None:
    for k in PATH_KEYS:
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None

def main() -> int:
    paths: list[str] = []
    seen: set[str] = set()

    bad_json = 0
    no_path = 0

    with open(JSONL_PATH, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                bad_json += 1
                continue

            p = pick_path(obj)
            if not p:
                no_path += 1
                continue

            if p not in seen:
                seen.add(p)
                paths.append(p)

    missing = 0
    unreadable = 0
    written_files = 0
    bytes_written = 0

    run_header = (
        f"# honeypot sample dump\n"
        f"# jsonl: {JSONL_PATH}\n"
        f"# created: {datetime.utcnow().isoformat()}Z\n"
        f"# unique_paths: {len(paths)}\n"
        f"# bad_json_lines: {bad_json}\n"
        f"# no_path_lines: {no_path}\n"
        "\n"
    )

    with open(OUT_TXT, "w", encoding="utf-8", errors="replace") as out:
        out.write(run_header)

        for p in paths:
            if not os.path.isfile(p):
                missing += 1
                continue

            try:
                with open(p, "rb") as sample:
                    data = sample.read()
            except Exception:
                unreadable += 1
                continue

            out.write("\n" + "=" * 100 + "\n")
            out.write(f"FILE: {p}\n")
            out.write("=" * 100 + "\n")

            # Decode binary safely (lossy, but keeps byte values stable-ish)
            text = data.decode("latin-1", errors="replace")
            out.write(text)

            written_files += 1
            bytes_written += len(text.encode("utf-8", errors="replace"))

    with open(OUT_MANIFEST, "w", encoding="utf-8") as mf:
        mf.write(run_header)
        mf.write("# paths (in write order)\n")
        for p in paths:
            mf.write(p + "\n")
        mf.write("\n")
        mf.write(f"# written_files: {written_files}\n")
        mf.write(f"# missing_files: {missing}\n")
        mf.write(f"# unreadable_files: {unreadable}\n")

    print(f"[+] Combined output: {OUT_TXT}")
    print(f"[+] Manifest:        {OUT_MANIFEST}")
    print(f"[i] Unique paths:    {len(paths)}")
    print(f"[i] Written files:   {written_files}")
    print(f"[i] Missing files:   {missing}")
    print(f"[i] Unreadable:      {unreadable}")
    print(f"[i] Bad JSON lines:  {bad_json}")
    print(f"[i] No-path lines:   {no_path}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
