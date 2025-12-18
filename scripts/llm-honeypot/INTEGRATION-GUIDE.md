# T-Pot + LLM Integration Guide

This guide explains exactly how the LLM integration works with your existing T-Pot installation.

## How It Actually Works

### Architecture Overview

```
                          YOUR EXISTING T-POT (unchanged)
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   Attacker ──► Port 22 ──► Cowrie Container                            │
│                              │                                          │
│                              ├── Known commands (ls, cat, wget, etc.)  │
│                              │   └── Cowrie handles natively ✓         │
│                              │                                          │
│                              └── Unknown commands (docker, apt, etc.)  │
│                                  │                                      │
│                                  ▼                                      │
│   ┌──────────────────────────────────────────────────────────┐         │
│   │              NEW: LLM Proxy (port 11435)                  │         │
│   │  ┌─────────┐  ┌─────────────┐  ┌─────────────────────┐   │         │
│   │  │ Cache   │  │ Predictive  │  │ Session State       │   │         │
│   │  │ (Redis) │  │ Pre-fetch   │  │ Tracking            │   │         │
│   │  └────┬────┘  └──────┬──────┘  └──────────┬──────────┘   │         │
│   │       │              │                     │              │         │
│   │       └──────────────┴─────────────────────┘              │         │
│   │                        │                                  │         │
│   └────────────────────────┼──────────────────────────────────┘         │
│                            ▼                                            │
│   ┌─────────────────────────────────────────────────────────┐          │
│   │              NEW: Ollama (port 11434)                    │          │
│   │              Mistral 7B running locally                  │          │
│   │              Uses your 48 CPU cores                      │          │
│   └─────────────────────────────────────────────────────────┘          │
│                                                                         │
│   Logging: Cowrie's standard JSON ──► Your existing Filebeat ──► ES    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### What Changes in Your T-Pot?

**NOTHING in the core T-Pot containers changes.** We add a sidecar service.

| Component | Change? | Details |
|-----------|---------|---------|
| Cowrie container | Minimal | Add 1 Python file for LLM calls |
| Cowrie config | No | Uses existing settings |
| Cowrie logging | No | Same JSON format to same location |
| Filebeat | No | Already ingests Cowrie logs |
| Elasticsearch | No | Same indices |
| T-Pot network | No | LLM proxy joins existing network |

### The Key Insight: Cowrie Already Handles Most Commands

Cowrie has built-in emulation for ~50+ commands. The LLM is **only called for commands Cowrie doesn't know**:

```
COWRIE HANDLES NATIVELY (no LLM):     LLM HANDLES (rare):
─────────────────────────────         ───────────────────
ls, cat, cd, pwd                      docker ps
wget, curl                            apt install
ps, netstat, ss                       systemctl status
chmod, chown, mkdir, rm               pip install
uname, hostname, id, whoami           npm run
find, grep, head, tail                kubectl get
echo, env, export                     aws s3 ls
ssh, scp, ping                        terraform plan
su, sudo                              ...and other modern tools
```

This means:
1. **95%+ of attacker commands** → Instant Cowrie response (no latency)
2. **5% unusual commands** → LLM generates response (may have latency)

---

## How Realism is Maintained

### Problem: LLM Latency

Raw LLM call: 3-8 seconds on CPU
Real `ls` command: 5 milliseconds

**Solution: Predictive Pre-caching**

```python
# When attacker types:
$ cd /tmp

# We immediately pre-generate in background:
- "ls" response for /tmp
- "ls -la" response for /tmp
- "wget" with /tmp context
- "curl" with /tmp context

# So when they type the next command, it's already cached
$ ls -la
[Response is instant - was pre-generated]
```

### Problem: Filesystem Inconsistency

LLM might say a file exists, then not find it.

**Solution: Cowrie's Filesystem Takes Priority**

```
Attacker: echo "test" > /tmp/foo
          └── Cowrie handles this, creates virtual file

Attacker: cat /tmp/foo
          └── Cowrie checks virtual filesystem FIRST
          └── File exists? Return contents
          └── File doesn't exist? THEN call LLM
```

The LLM **never** handles file operations that Cowrie tracks.

### Problem: Session State

LLM doesn't remember what happened earlier.

**Solution: Session Context Injection**

```python
# Each LLM call includes:
system_prompt = f"""
Current directory: {session.cwd}
User: {session.username}
Previous commands: {session.history[-5:]}
Files created: {session.created_files}
"""
```

---

## How Cowrie Calls the LLM

The integration adds a single file to Cowrie that hooks into unknown command handling:

```python
# In Cowrie's command resolution:

def execute_command(cmd):
    # 1. Check built-in commands (ls, cat, etc.)
    if cmd in BUILTIN_COMMANDS:
        return builtin_handler(cmd)

    # 2. Check txtcmds (static text responses)
    if cmd in TXTCMDS:
        return txtcmds_handler(cmd)

    # 3. NEW: Check LLM proxy
    if LLM_ENABLED:
        response = call_llm_proxy(cmd, cwd, username)
        if response:
            return response

    # 4. Default: command not found
    return f"bash: {cmd}: command not found"
```

The `call_llm_proxy` function is a simple HTTP POST:

```python
def call_llm_proxy(cmd, cwd, username):
    response = requests.post("http://llm-proxy:11435/generate", json={
        "session_id": session.id,
        "command": cmd,
        "cwd": cwd,
        "username": username
    })
    return response.json().get("response")
```

---

## Logging: Completely Compatible

The LLM integration **adds** to Cowrie's logging, doesn't replace it:

### Standard Cowrie Log Entry
```json
{
  "eventid": "cowrie.command.input",
  "session": "abc123",
  "message": "CMD: docker ps",
  "timestamp": "2024-12-18T14:30:45.123Z",
  "src_ip": "192.168.1.100"
}
```

### With LLM Integration (same format, extra field)
```json
{
  "eventid": "cowrie.command.input",
  "session": "abc123",
  "message": "CMD: docker ps",
  "timestamp": "2024-12-18T14:30:45.123Z",
  "src_ip": "192.168.1.100",
  "response_source": "llm",        // NEW: where response came from
  "response_latency_ms": 145       // NEW: how long it took
}
```

Your existing:
- Filebeat config → **works unchanged**
- Elasticsearch indices → **works unchanged**
- Grafana dashboards → **works unchanged**
- ELKIE pipelines → **works unchanged**

---

## How to Spot AI (And How We Mitigate)

### Tell #1: Response Latency

**Problem**: `ls` taking 5 seconds is suspicious

**Mitigation**:
- Cowrie handles `ls` natively (instant)
- Only rare commands go to LLM
- Pre-caching reduces LLM calls
- Artificial jitter masks patterns

### Tell #2: Inconsistent Responses

**Problem**: Same command gives different output

**Mitigation**:
- Response caching (same input → same output)
- Low temperature (0.3) for deterministic generation
- Session state tracking

### Tell #3: Too Helpful

**Problem**: LLM might give detailed explanations

**Mitigation**:
- System prompt enforces terse output
- Stop tokens prevent rambling
- Response cleaning removes artifacts

### Tell #4: Wrong Error Messages

**Problem**: LLM might invent error formats

**Mitigation**:
- Examples in system prompt
- Real bash errors for fallback
- Cowrie handles most errors natively

### What Still Might Reveal It

Sophisticated attackers running:
```bash
# Timing attacks
for i in {1..10}; do time docker ps; done

# Consistency checks
docker ps > /tmp/a && docker ps > /tmp/b && diff /tmp/a /tmp/b

# Obscure commands
awk 'BEGIN{print systime()}'
```

**Reality check**: Most attackers are running automated scripts that don't do this level of verification. They're looking for easy targets, not debugging honeypots.

---

## Installation Steps

### Step 1: Start LLM Services

```bash
cd /home/user/ELKIE/scripts/llm-honeypot

# Start Ollama and the proxy
docker compose -f docker-compose.tpot-integration.yml up -d

# Pull the model (first time only, takes ~5 minutes)
docker exec honeypot-ollama ollama pull mistral:7b-instruct-v0.2-q4_K_M
```

### Step 2: Add Plugin to Cowrie

```bash
# Copy the LLM handler to Cowrie's custom commands
docker cp cowrie-plugin/llm_command_handler.py cowrie:/cowrie/cowrie-git/src/cowrie/commands/

# Restart Cowrie to load the plugin
docker restart cowrie
```

### Step 3: Verify Integration

```bash
# Check LLM proxy is running
curl http://localhost:11435/health

# Test an LLM command
curl -X POST http://localhost:11435/generate \
  -H "Content-Type: application/json" \
  -d '{"command": "docker ps", "cwd": "/root", "username": "root"}'

# Connect and test
ssh root@localhost -p 2222
# Password: whatever Cowrie accepts

$ docker ps  # This goes to LLM
$ ls         # This is handled by Cowrie natively
```

---

## Resource Usage

On your Dual Xeon Platinum 8168 with 96GB RAM:

| Component | CPU | RAM | Notes |
|-----------|-----|-----|-------|
| Ollama + Mistral 7B | 10-48 cores (burst) | ~12GB | Only during generation |
| LLM Proxy | 1 core | ~200MB | Mostly idle |
| Redis Cache | 0.5 core | ~1GB | Response cache |
| **Total Added** | **~2 cores avg** | **~14GB** | Leaves 80GB+ for T-Pot |

---

## Summary

| Question | Answer |
|----------|--------|
| Do I modify T-Pot containers? | Minimally - add 1 file to Cowrie |
| Does logging change? | No - same format, same location |
| How is it realistic? | Cowrie handles 95% of commands; LLM only for rare ones |
| What about latency? | Pre-caching + Cowrie native = most responses instant |
| Can attackers detect it? | Sophisticated ones maybe; script kiddies no |
| How does Cowrie integrate? | HTTP call to LLM proxy for unknown commands |
