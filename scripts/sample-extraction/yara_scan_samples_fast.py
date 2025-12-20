#!/usr/bin/env python3
"""
YARA Scanner for Honeypot Samples - OPTIMIZED VERSION

Key improvements over original:
1. Uses yara-python library (no subprocess overhead)
2. Compiles all rules ONCE upfront
3. Scans with timeout per sample (not per rule)
4. Progress bar with ETA
5. Skips problematic files gracefully

Usage:
    pip install yara-python
    python3 yara_scan_samples_fast.py --rules-dir /path/to/rules --samples-dir /path/to/samples
"""

import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout
from multiprocessing import cpu_count

try:
    import yara
except ImportError:
    print("[!] yara-python not installed. Run: pip install yara-python")
    sys.exit(1)


# Defaults
DEFAULT_RULES_DIR = os.path.expanduser("~/rules")
DEFAULT_SAMPLES_DIR = "/opt/honeypot-quarantine"
DEFAULT_TPOT_SAMPLES = "/data/cowrie/downloads"
OUT_FULL = os.path.expanduser("~/yara_scan_results.txt")
OUT_MATCHES = os.path.expanduser("~/yara_matches_only.txt")
OUT_JSON = os.path.expanduser("~/yara_matches.json")

# Limits
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
SCAN_TIMEOUT = 30  # seconds per file


def find_yara_rules(rules_dir: str) -> list:
    """Find all .yar and .yara files recursively."""
    rules = []
    for ext in ("*.yar", "*.yara"):
        rules.extend(Path(rules_dir).rglob(ext))
    return [str(r) for r in rules]


def compile_rules(rules_dir: str) -> tuple:
    """Compile all YARA rules into a single object. Returns (rules, errors)."""
    rule_files = find_yara_rules(rules_dir)

    if not rule_files:
        return None, ["No YARA rule files found"]

    print(f"[+] Compiling {len(rule_files)} YARA rule files...")

    errors = []
    compiled_sources = {}

    for rule_file in rule_files:
        namespace = Path(rule_file).stem
        try:
            # Test compile individually to catch errors
            yara.compile(filepath=rule_file)
            compiled_sources[namespace] = rule_file
        except yara.SyntaxError as e:
            errors.append(f"Syntax error in {rule_file}: {e}")
        except yara.Error as e:
            errors.append(f"Error in {rule_file}: {e}")

    if not compiled_sources:
        return None, errors

    # Compile all valid rules together
    try:
        rules = yara.compile(filepaths=compiled_sources)
        print(f"[+] Successfully compiled {len(compiled_sources)} rule files")
        return rules, errors
    except Exception as e:
        return None, errors + [f"Failed to compile rules: {e}"]


def find_samples(samples_dir: str) -> list:
    """Find all sample files to scan."""
    samples = []

    if not os.path.isdir(samples_dir):
        return samples

    for root, dirs, files in os.walk(samples_dir):
        for f in files:
            # Skip metadata files
            if f.endswith(('.name', '.json', '.txt', '.log', '.md')):
                continue

            filepath = os.path.join(root, f)

            try:
                size = os.path.getsize(filepath)
                if size > MAX_FILE_SIZE:
                    continue
                if size == 0:
                    continue

                samples.append({
                    "path": filepath,
                    "name": f,
                    "size": size
                })
            except OSError:
                continue

    return samples


def scan_file(args: tuple) -> dict:
    """Scan a single file with compiled YARA rules."""
    filepath, rules_data = args

    result = {
        "path": filepath,
        "matches": [],
        "error": None,
        "scan_time_ms": 0
    }

    start = time.time()

    try:
        # Recompile rules in subprocess (can't pickle compiled rules)
        rules = yara.compile(filepaths=rules_data)

        # Scan with timeout
        matches = rules.match(filepath, timeout=SCAN_TIMEOUT)

        for match in matches:
            result["matches"].append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta) if match.meta else {}
            })

    except yara.TimeoutError:
        result["error"] = "Scan timeout"
    except yara.Error as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    result["scan_time_ms"] = int((time.time() - start) * 1000)
    return result


def xxd_dump(filepath: str, max_bytes: int = 256) -> str:
    """Generate xxd-style hex dump."""
    try:
        with open(filepath, "rb") as f:
            data = f.read(max_bytes)
    except:
        return "(unable to read file)"

    lines = []
    bytes_per_line = 16

    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]
        hex_parts = [f"{b:02x}" for b in chunk]
        hex_str = " ".join(hex_parts)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08x}: {hex_str:<48} {ascii_str}")

    if len(data) == max_bytes:
        lines.append(f"... (showing first {max_bytes} bytes)")

    return "\n".join(lines)


def format_time(seconds: float) -> str:
    """Format seconds as human-readable time."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"


def main():
    parser = argparse.ArgumentParser(description="Fast YARA scanner for honeypot samples")
    parser.add_argument("--rules-dir", default=DEFAULT_RULES_DIR, help="Directory containing YARA rules")
    parser.add_argument("--samples-dir", default=None, help="Directory containing samples to scan")
    parser.add_argument("--workers", type=int, default=min(4, cpu_count()), help="Number of parallel workers")
    parser.add_argument("--timeout", type=int, default=SCAN_TIMEOUT, help="Timeout per file in seconds")
    args = parser.parse_args()

    global SCAN_TIMEOUT
    SCAN_TIMEOUT = args.timeout

    # Find rules directory
    if not os.path.isdir(args.rules_dir):
        print(f"[!] Rules directory not found: {args.rules_dir}")
        print("    Use --rules-dir /path/to/rules")
        return 1

    # Find samples directory
    samples_dir = args.samples_dir
    if samples_dir is None:
        # Try common locations
        for path in [DEFAULT_SAMPLES_DIR, DEFAULT_TPOT_SAMPLES, "/data/dionaea/binaries"]:
            if os.path.isdir(path):
                samples_dir = path
                break

    if samples_dir is None or not os.path.isdir(samples_dir):
        print(f"[!] Samples directory not found")
        print("    Use --samples-dir /path/to/samples")
        return 1

    print(f"[+] Rules directory: {args.rules_dir}")
    print(f"[+] Samples directory: {samples_dir}")

    # Compile rules
    rules, errors = compile_rules(args.rules_dir)

    if errors:
        print(f"[!] {len(errors)} rule compilation errors:")
        for err in errors[:5]:
            print(f"    {err}")
        if len(errors) > 5:
            print(f"    ... and {len(errors) - 5} more")

    if rules is None:
        print("[!] No valid rules compiled, exiting")
        return 1

    # Get rule file paths for subprocess workers
    rule_files = find_yara_rules(args.rules_dir)
    rules_data = {Path(r).stem: r for r in rule_files}

    # Find samples
    print(f"[+] Scanning for samples in {samples_dir}...")
    samples = find_samples(samples_dir)
    print(f"[+] Found {len(samples)} samples to scan")

    if not samples:
        print("[!] No samples found")
        return 1

    # Scan samples
    print(f"[+] Scanning with {args.workers} workers, {args.timeout}s timeout per file...")
    print()

    all_matches = []
    scanned = 0
    matched = 0
    errors_count = 0
    start_time = time.time()

    timestamp = datetime.utcnow().isoformat() + "Z"

    with open(OUT_FULL, "w") as full_out, \
         open(OUT_MATCHES, "w") as match_out:

        header = f"""# YARA Scan Results
# Date: {timestamp}
# Rules: {args.rules_dir} ({len(rule_files)} files)
# Samples: {len(samples)}
# Workers: {args.workers}

"""
        full_out.write(header)
        match_out.write(header)

        # Process samples (single-threaded for reliability)
        for sample in samples:
            scanned += 1
            filepath = sample["path"]

            # Progress with ETA
            elapsed = time.time() - start_time
            if scanned > 1:
                eta = (elapsed / (scanned - 1)) * (len(samples) - scanned)
                eta_str = format_time(eta)
            else:
                eta_str = "..."

            print(f"\r[{scanned}/{len(samples)}] ETA: {eta_str} | Matches: {matched} | Scanning: {sample['name'][:30]}...", end="", flush=True)

            # Scan file
            try:
                matches = rules.match(filepath, timeout=SCAN_TIMEOUT)

                file_matches = []
                for match in matches:
                    file_matches.append({
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": list(match.tags)
                    })

                # Write to full report
                full_out.write("\n" + "=" * 80 + "\n")
                full_out.write(f"FILE: {filepath}\n")
                full_out.write(f"SIZE: {sample['size']} bytes\n")

                if file_matches:
                    matched += 1
                    full_out.write(f"MATCHES: {len(file_matches)}\n")
                    for m in file_matches:
                        full_out.write(f"  [!] {m['rule']} ({m['namespace']})\n")
                        match_out.write(f"{sample['name']} | {m['rule']} | {m['namespace']}\n")
                        all_matches.append(m)
                else:
                    full_out.write("MATCHES: None\n")

                full_out.write("-" * 40 + "\n")
                full_out.write(xxd_dump(filepath) + "\n")

            except yara.TimeoutError:
                errors_count += 1
                full_out.write(f"\n[TIMEOUT] {filepath}\n")
            except Exception as e:
                errors_count += 1
                full_out.write(f"\n[ERROR] {filepath}: {e}\n")

    # Summary
    elapsed = time.time() - start_time
    print("\r" + " " * 100)  # Clear line
    print(f"\n[+] Scan complete in {format_time(elapsed)}")
    print(f"    Scanned: {scanned}")
    print(f"    Matched: {matched} samples ({len(all_matches)} rule hits)")
    print(f"    Errors:  {errors_count}")
    print(f"\n[+] Reports saved:")
    print(f"    {OUT_FULL}")
    print(f"    {OUT_MATCHES}")

    # Show top matches
    if all_matches:
        print(f"\n[!] Top YARA matches:")
        rule_counts = {}
        for m in all_matches:
            rule_counts[m['rule']] = rule_counts.get(m['rule'], 0) + 1
        for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"    {rule}: {count}")

    # Save JSON for Elasticsearch
    with open(OUT_JSON, "w") as f:
        json.dump({
            "timestamp": timestamp,
            "samples_scanned": scanned,
            "samples_matched": matched,
            "total_matches": len(all_matches),
            "matches": all_matches
        }, f, indent=2)

    return 0


if __name__ == "__main__":
    sys.exit(main())
