#!/usr/bin/env python3
"""
Scan all extracted honeypot samples with YARA rules.

Outputs:
  - ~/yara_scan_results.txt    (full report with matches + hex dumps)
  - ~/yara_matches_only.txt    (just the matches for quick review)

Usage:
    sudo python3 yara_scan_samples.py
    sudo python3 yara_scan_samples.py --rules-dir /path/to/rules
"""

import json
import os
import sys
import subprocess
from datetime import datetime
from pathlib import Path

# Defaults
JSONL_PATH = "/var/log/honeypot-extraction/samples.jsonl"
RULES_DIR = os.path.expanduser("~/rules")
OUT_FULL = os.path.expanduser("~/yara_scan_results.txt")
OUT_MATCHES = os.path.expanduser("~/yara_matches_only.txt")
QUARANTINE_BASE = "/opt/honeypot-quarantine"

def xxd_dump(data: bytes, bytes_per_line: int = 16, max_bytes: int = 512) -> str:
    """Generate xxd-style hex dump (truncated for large files)."""
    truncated = len(data) > max_bytes
    data = data[:max_bytes]

    lines = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]
        hex_parts = []
        for i, b in enumerate(chunk):
            hex_parts.append(f"{b:02x}")
            if i == 7:
                hex_parts.append("")
        hex_str = " ".join(hex_parts)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08x}: {hex_str:<49} {ascii_str}")

    if truncated:
        lines.append(f"... (truncated, showing first {max_bytes} of {len(data)} bytes)")

    return "\n".join(lines) + "\n"


def find_yara_rules(rules_dir: str) -> list:
    """Find all .yar and .yara files recursively."""
    rules = []
    for ext in ("*.yar", "*.yara"):
        rules.extend(Path(rules_dir).rglob(ext))
    return [str(r) for r in rules]


def scan_with_yara(filepath: str, rules_dir: str) -> list:
    """Scan a file with all YARA rules, return list of matches."""
    matches = []

    # Find all rule files
    rule_files = find_yara_rules(rules_dir)

    for rule_file in rule_files:
        try:
            result = subprocess.run(
                ["yara", "-r", rule_file, filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    if line:
                        # Format: "RuleName filepath"
                        parts = line.split(" ", 1)
                        if parts:
                            matches.append({
                                "rule": parts[0],
                                "rule_file": os.path.basename(rule_file)
                            })
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue

    return matches


def get_samples_from_jsonl(jsonl_path: str) -> list:
    """Read sample paths from the JSONL catalog."""
    samples = []
    seen = set()

    if not os.path.exists(jsonl_path):
        return samples

    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                path = obj.get("quarantine_path") or obj.get("original_path")
                if path and path not in seen:
                    seen.add(path)
                    samples.append({
                        "path": path,
                        "sha256": obj.get("sha256", "unknown"),
                        "container": obj.get("container", "unknown"),
                        "file_type": obj.get("file_type", "unknown")
                    })
            except json.JSONDecodeError:
                continue

    return samples


def get_samples_from_filesystem(quarantine_base: str) -> list:
    """Fallback: find samples directly from filesystem."""
    samples = []

    for root, dirs, files in os.walk(quarantine_base):
        for f in files:
            if f.endswith(".name") or f.endswith(".json"):
                continue
            filepath = os.path.join(root, f)
            samples.append({
                "path": filepath,
                "sha256": f,
                "container": os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(filepath)))),
                "file_type": "unknown"
            })

    return samples


def main() -> int:
    # Parse args
    rules_dir = RULES_DIR
    for i, arg in enumerate(sys.argv):
        if arg == "--rules-dir" and i + 1 < len(sys.argv):
            rules_dir = sys.argv[i + 1]

    if not os.path.isdir(rules_dir):
        print(f"[!] Rules directory not found: {rules_dir}")
        print("    Use --rules-dir /path/to/rules")
        return 1

    # Find YARA rules
    rule_files = find_yara_rules(rules_dir)
    print(f"[+] Found {len(rule_files)} YARA rule files in {rules_dir}")

    # Get samples
    samples = get_samples_from_jsonl(JSONL_PATH)
    if not samples:
        print(f"[i] No samples in JSONL, scanning filesystem...")
        samples = get_samples_from_filesystem(QUARANTINE_BASE)

    print(f"[+] Found {len(samples)} samples to scan")

    if not samples:
        print("[!] No samples found")
        return 1

    # Scan each sample
    all_matches = []
    scanned = 0
    matched = 0

    timestamp = datetime.utcnow().isoformat() + "Z"

    with open(OUT_FULL, "w", encoding="utf-8") as full_out, \
         open(OUT_MATCHES, "w", encoding="utf-8") as match_out:

        header = f"""# YARA Scan Results
# Date: {timestamp}
# Rules: {rules_dir} ({len(rule_files)} files)
# Samples: {len(samples)}

"""
        full_out.write(header)
        match_out.write(header)

        for sample in samples:
            path = sample["path"]

            if not os.path.isfile(path):
                continue

            scanned += 1
            print(f"[{scanned}/{len(samples)}] Scanning: {os.path.basename(path)[:40]}...", end="\r")

            # Scan with YARA
            matches = scan_with_yara(path, rules_dir)

            # Read file content for hex dump
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except:
                data = b""

            # Write to full report
            full_out.write("\n" + "=" * 100 + "\n")
            full_out.write(f"FILE: {path}\n")
            full_out.write(f"SHA256: {sample['sha256']}\n")
            full_out.write(f"Container: {sample['container']}\n")
            full_out.write(f"Size: {len(data)} bytes\n")

            if matches:
                matched += 1
                full_out.write(f"YARA MATCHES: {len(matches)}\n")
                for m in matches:
                    full_out.write(f"  [!] {m['rule']} (from {m['rule_file']})\n")
                    match_out.write(f"{sample['sha256']} | {m['rule']} | {m['rule_file']} | {sample['container']}\n")
                all_matches.extend(matches)
            else:
                full_out.write("YARA MATCHES: None\n")

            full_out.write("-" * 50 + "\n")
            full_out.write(xxd_dump(data))

    print(" " * 80)  # Clear progress line
    print(f"\n[+] Scan complete!")
    print(f"    Scanned: {scanned} samples")
    print(f"    Matched: {matched} samples ({len(all_matches)} total rule hits)")
    print(f"\n[+] Full report: {OUT_FULL}")
    print(f"[+] Matches only: {OUT_MATCHES}")

    if all_matches:
        print(f"\n[!] YARA MATCHES FOUND:")
        # Dedupe and count
        rule_counts = {}
        for m in all_matches:
            rule_counts[m['rule']] = rule_counts.get(m['rule'], 0) + 1
        for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
            print(f"    {rule}: {count}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
