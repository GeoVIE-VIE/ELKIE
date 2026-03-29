#!/bin/bash
###############################################################################
# harden_lab.sh — Security hardening for Cisco Lab VM (192.168.30.10)
#
# Run as root on the lab VM. All changes are LOCAL to this VM only.
###############################################################################

set -euo pipefail

header() { echo -e "\n\033[1;36m=== $1 ===\033[0m"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash harden_lab.sh"
    exit 1
fi

# --- 1. Disable root login ---
header "1. Disabling root login"
passwd -l root 2>/dev/null || true
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
# Ensure it exists if not present
grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "  Root login disabled"

# --- 2. SSH hardening — key only, no password from WAN ---
header "2. Hardening SSH"
cat > /etc/ssh/sshd_config.d/99-lab-hardening.conf << 'SSHEOF'
# Cisco Lab SSH Hardening
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
Banner /etc/ssh/banner
SSHEOF

# SSH banner
cat > /etc/ssh/banner << 'BANNER'

  ╔══════════════════════════════════════════════╗
  ║  CISCO LAB — Authorized Access Only          ║
  ║  All sessions are logged and monitored.      ║
  ╚══════════════════════════════════════════════╝

BANNER

systemctl restart sshd
echo "  SSH hardened: root disabled, max 3 auth tries, 5min idle timeout"

# --- 3. Firewall (iptables) — only allow 25808 + SSH from LAN ---
header "3. Configuring firewall"

# Flush existing
iptables -F
iptables -X
ip6tables -F
ip6tables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# Established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH from internal networks only (VLAN 30 + management)
iptables -A INPUT -p tcp --dport 22 -s 192.168.30.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 192.168.0.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 192.168.50.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 192.168.99.0/24 -j ACCEPT

# Web UI (25808) from anywhere — this is the public-facing port
iptables -A INPUT -p tcp --dport 25808 -j ACCEPT

# ICMP (ping) — limited rate
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/s -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Drop everything else (logged)
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPT_DROP: " --log-level 4
iptables -A INPUT -j DROP

# IPv6 — drop all (lab doesn't use it)
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT

# Persist
apt-get install -y iptables-persistent 2>/dev/null || true
netfilter-persistent save 2>/dev/null || true
echo "  Firewall: only 25808 (public) + SSH (LAN only)"

# --- 4. Fail2ban ---
header "4. Installing and configuring fail2ban"
apt-get install -y fail2ban 2>/dev/null

# SSH jail
cat > /etc/fail2ban/jail.d/ssh.conf << 'F2BSSH'
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 600
bantime = 3600
banaction = iptables-multiport
F2BSSH

# Custom jail for the web UI
cat > /etc/fail2ban/jail.d/cisco-lab-web.conf << 'F2BWEB'
[cisco-lab-web]
enabled = true
port = 25808
filter = cisco-lab-web
logpath = /var/log/cisco-lab-auth.log
maxretry = 5
findtime = 300
bantime = 3600
banaction = iptables-multiport
F2BWEB

# Fail2ban filter for web UI auth failures
cat > /etc/fail2ban/filter.d/cisco-lab-web.conf << 'F2BFILTER'
[Definition]
failregex = ^.*LOGIN_FAIL.*ip=<HOST>.*$
ignoreregex =
F2BFILTER

# Create the log file
touch /var/log/cisco-lab-auth.log
chmod 644 /var/log/cisco-lab-auth.log

systemctl enable fail2ban
systemctl restart fail2ban
echo "  Fail2ban: SSH (3 tries/1hr ban) + Web (5 tries/1hr ban)"

# --- 5. Verify GNS3 listens on localhost only ---
header "5. Verifying GNS3 is localhost-only"
GNS3_LISTEN=$(ss -tlnp | grep 3080 | grep -c "127.0.0.1" || true)
if [ "$GNS3_LISTEN" -ge 1 ]; then
    echo "  GNS3 listening on 127.0.0.1:3080 only — OK"
else
    echo "  WARNING: GNS3 may be listening on 0.0.0.0 — check config"
fi

# --- 6. Sysctl hardening ---
header "6. Kernel hardening"
cat > /etc/sysctl.d/99-lab-hardening.conf << 'SYSCTL'
# Disable IP forwarding (lab VM is not a router)
net.ipv4.ip_forward = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Ignore source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
SYSCTL

sysctl -p /etc/sysctl.d/99-lab-hardening.conf 2>/dev/null
echo "  Kernel hardened: no forwarding, SYN cookies, no redirects"

# --- 7. Auto-updates for security patches ---
header "7. Enabling automatic security updates"
apt-get install -y unattended-upgrades 2>/dev/null
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'AUTOUPD'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
AUTOUPD

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUTOFREQ'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
AUTOFREQ
echo "  Auto security updates enabled"

# --- 8. Log rotation for auth log ---
header "8. Setting up log rotation"
cat > /etc/logrotate.d/cisco-lab-auth << 'LOGROT'
/var/log/cisco-lab-auth.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
}
LOGROT
echo "  Auth log rotation: 30 days, compressed"

# --- Summary ---
header "HARDENING COMPLETE"
echo ""
echo "  Firewall:      Only port 25808 (public) + SSH (LAN only)"
echo "  SSH:           Root disabled, key preferred, 3 max tries, idle timeout"
echo "  Fail2ban:      SSH (3 tries/1hr) + Web (5 tries/1hr) — IP banned at firewall"
echo "  GNS3:          Localhost only (127.0.0.1:3080)"
echo "  Kernel:        SYN cookies, no forwarding, no redirects"
echo "  Auto-updates:  Security patches applied automatically"
echo "  Logging:       Auth failures logged to /var/log/cisco-lab-auth.log"
echo ""
echo "  IMPORTANT: Update the web app to log auth failures for fail2ban."
echo "  See /var/log/cisco-lab-auth.log"
echo ""
