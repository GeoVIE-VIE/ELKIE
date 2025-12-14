# Understanding YARA Rules

YARA rules are pattern-matching signatures for identifying malware. Here's how to read them:

## Basic Rule Structure

```yara
rule Mirai_Botnet {
    meta:
        author = "Security Researcher"
        description = "Detects Mirai botnet variants"
        severity = "high"

    strings:
        $s1 = "busybox" ascii
        $s2 = "/bin/sh" ascii
        $s3 = { 7F 45 4C 46 }  // ELF magic bytes
        $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

    condition:
        $s3 at 0 and (2 of ($s1, $s2, $ip))
}
```

## Key Components

| Section | Purpose |
|---------|---------|
| `meta:` | Metadata - author, description, severity, references |
| `strings:` | Patterns to search for in the file |
| `condition:` | Logic for when the rule triggers |

## String Types

| Syntax | Type | Example |
|--------|------|---------|
| `"text"` | ASCII string | `$a = "password"` |
| `"text" wide` | UTF-16 string | `$b = "admin" wide` |
| `{ AA BB CC }` | Hex bytes | `$c = { 4D 5A }` (MZ header) |
| `/regex/` | Regular expression | `$d = /https?:\/\//` |

## Common Conditions

| Condition | Meaning |
|-----------|---------|
| `all of them` | All defined strings must match |
| `any of them` | At least one string matches |
| `2 of ($a, $b, $c)` | At least 2 of the 3 strings match |
| `$a at 0` | String $a at file offset 0 |
| `filesize < 1MB` | File size constraint |
| `uint16(0) == 0x5A4D` | MZ header check (PE files) |

## Your Rules Directory

Your `~/rules` folder contains community YARA rules. Key categories:

```
~/rules/
├── malware/           # Known malware families
│   ├── RAT/          # Remote Access Trojans
│   ├── Ransomware/   # Ransomware variants
│   └── Botnet/       # Botnet signatures
├── exploits/         # Exploit kit patterns
├── packers/          # Packed/obfuscated binaries
└── webshells/        # Web shell detection
```

## Interpreting Matches

When you see a YARA match like:

```
e3b0c44298fc... | Mirai_Variant_1 | malware_mirai.yar | cowrie
```

This means:
- **SHA256**: `e3b0c44298fc...` - the sample hash
- **Rule**: `Mirai_Variant_1` - the specific signature that matched
- **Rule File**: `malware_mirai.yar` - which .yar file contains the rule
- **Source**: `cowrie` - which honeypot caught it

## What To Do With Matches

1. **Check VirusTotal**: `curl https://www.virustotal.com/gui/file/<sha256>`
2. **Read the rule**: Find the .yar file and see what triggered it
3. **Analyze the sample**: Use `xxd`, `strings`, `file` commands
4. **Document**: Note attacker IP, timestamp, attack vector

## No Matches?

0 YARA matches doesn't mean samples are clean. It could mean:
- Samples are small probes/scanners (not full malware)
- New/unknown malware family (not in rules yet)
- Obfuscated/packed binaries

Consider submitting unknown samples to:
- VirusTotal (if allowed by your policy)
- MalwareBazaar
- Any-Run sandbox

## Adding Custom Rules

Create `~/rules/custom/honeypot-custom.yar`:

```yara
rule Suspicious_Wget_Curl {
    meta:
        description = "Script downloading additional payloads"
    strings:
        $wget = "wget " ascii
        $curl = "curl " ascii
        $chmod = "chmod +x" ascii
        $sh = "/bin/sh" ascii
    condition:
        ($wget or $curl) and $chmod and $sh
}
```

Then it will be picked up on next extraction run.
