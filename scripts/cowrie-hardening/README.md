# Cowrie Hardening for T-Pot

Makes your Cowrie honeypot less detectable by automated attack tools.

## What Automated Tools Check

| Check | Default Cowrie | After Hardening |
|-------|---------------|-----------------|
| `/proc/cpuinfo` | Missing/fake | Realistic 4-core Xeon |
| `/proc/meminfo` | Missing/fake | Realistic 16GB |
| `/etc/passwd` | Minimal users | Full Ubuntu user list |
| `ps aux` | Few processes | nginx, mysql, sshd, etc. |
| `netstat -tulpn` | Empty/fake | Realistic web server |
| `uname -a` | Old kernel | Current Ubuntu 22.04 |
| SSH banner | Generic | Real Ubuntu MOTD |
| Uptime | 0 or weird | 42 days realistic |

## Installation

```bash
cd /home/user/ELKIE/scripts/cowrie-hardening
./install.sh
```

This will:
1. Detect your Cowrie container
2. Backup existing txtcmds
3. Install hardened command outputs
4. Restart Cowrie

## Files Installed

```
txtcmds/bin/
├── cat__/etc/passwd       # Realistic user list
├── cat__/etc/os-release   # Ubuntu 22.04
├── cat__/proc/cpuinfo     # 4-core Xeon Gold
├── cat__/proc/meminfo     # 16GB RAM
├── df__-h                 # Realistic disk usage
├── free__-h               # Realistic memory
├── lsb_release__-a        # Ubuntu 22.04
├── netstat__-tulpn        # nginx, mysql, sshd
├── ps__aux                # Realistic processes
├── uname__-a              # Current kernel
└── uptime                 # 42 days uptime
```

## Customization

Edit the files in `txtcmds/bin/` to match your "fake" server profile:

- **Web server?** Keep nginx in ps/netstat
- **Database server?** Keep mysql
- **Docker host?** Add docker processes
- **Different distro?** Edit os-release, lsb_release

### Tips for Realism

1. **Match your real infrastructure** - If you run CentOS servers, make the honeypot look like CentOS
2. **Update versions** - Keep kernel/OS versions current
3. **Consistent story** - If you have mysql, have /var/lib/mysql, mysql user, etc.
4. **Realistic uptime** - Don't use 0 or 999 days

## Manual Installation

If you prefer to install manually:

```bash
# Copy individual files
docker cp txtcmds/bin/ps__aux cowrie:/cowrie/cowrie-git/share/cowrie/txtcmds/bin/

# Restart Cowrie
docker restart cowrie
```

## Verify Installation

```bash
# SSH into honeypot
ssh root@your-ip -p 2222

# Test commands
cat /proc/cpuinfo
ps aux
netstat -tulpn
```

## What This Doesn't Fix

- **Timing** - Command response times still instant
- **Filesystem inconsistency** - Can't create real files
- **Network** - Can't make real outbound connections
- **Advanced fingerprinting** - Sophisticated tools may still detect

For higher interaction, consider the LLM integration in `../llm-honeypot/`.
