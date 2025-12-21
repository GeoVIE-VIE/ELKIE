#!/bin/bash
#
# Sacrificial VM Setup Script
#
# Run this on a fresh Ubuntu 22.04 VM to configure it as a high-interaction honeypot.
# The VM will look like a "forgotten" development server.
#
# What this installs:
# 1. Weak credentials (for Cowrie to use)
# 2. Auditd - logs ALL commands invisibly
# 3. Osquery - system state monitoring
# 4. Suricata - network traffic capture
# 5. Filebeat - ships logs to your Elasticsearch
# 6. Fake services to look realistic
#
# Usage: sudo ./setup-sacrificial-vm.sh <ELASTICSEARCH_HOST> <HONEYPOT_VLAN_GW>
#

set -e

ELASTICSEARCH_HOST="${1:-192.168.40.1:9200}"
HONEYPOT_GW="${2:-192.168.40.1}"
VM_IP=$(hostname -I | awk '{print $1}')

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     Sacrificial Honeypot VM Setup                              ║"
echo "║     High-Interaction Honeypot with Full Monitoring             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo "Configuration:"
echo "  VM IP:              $VM_IP"
echo "  Elasticsearch:      $ELASTICSEARCH_HOST"
echo "  Gateway:            $HONEYPOT_GW"
echo ""

# ============================================================================
# STEP 1: Create honeypot user for Cowrie backend
# ============================================================================
echo -e "${BLUE}[1/8] Creating honeypot backend user...${NC}"

# User that Cowrie uses to connect (not what attacker sees)
if ! id "honeypot" &>/dev/null; then
    useradd -m -s /bin/bash honeypot
    echo "honeypot:honeypot_backend_pass_change_me" | chpasswd
fi

# Make it look like a dev server - add realistic users
for user in admin developer deploy jenkins; do
    if ! id "$user" &>/dev/null; then
        useradd -m -s /bin/bash "$user"
    fi
done

# Set WEAK passwords that attackers will try (Cowrie harvests these)
echo "root:root" | chpasswd
echo "admin:admin" | chpasswd
echo "developer:developer" | chpasswd
echo "deploy:deploy123" | chpasswd

# Enable password auth for SSH
sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

systemctl restart sshd

echo -e "${GREEN}  ✓ Users created with weak passwords${NC}"

# ============================================================================
# STEP 2: Install auditd for invisible command logging
# ============================================================================
echo -e "${BLUE}[2/8] Installing auditd for command logging...${NC}"

apt-get update -qq
apt-get install -y -qq auditd audispd-plugins

# Configure audit rules - log EVERYTHING
cat > /etc/audit/rules.d/honeypot.rules << 'EOF'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode - silent (don't alert attacker)
-f 1

# Log all execve calls (every command run)
-a always,exit -F arch=b64 -S execve -k command
-a always,exit -F arch=b32 -S execve -k command

# Log all file access
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EACCES -k file_access
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EPERM -k file_access

# Log network connections
-a always,exit -F arch=b64 -S connect -k network
-a always,exit -F arch=b64 -S accept -k network
-a always,exit -F arch=b64 -S bind -k network

# Log file modifications
-a always,exit -F arch=b64 -S rename,unlink,chmod,chown -k file_modify

# Log all writes to /tmp and /var/tmp (malware staging)
-w /tmp -p wa -k tmp_write
-w /var/tmp -p wa -k tmp_write

# Log SSH activity
-w /etc/ssh -p wa -k ssh_config

# Log cron modifications
-w /etc/crontab -p wa -k cron
-w /var/spool/cron -p wa -k cron

# Log sudo/su usage
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc

# Make config immutable (attacker can't disable)
-e 2
EOF

# Enable audit logging in JSON format (easier to parse)
sed -i 's/log_format = .*/log_format = ENRICHED/' /etc/audit/auditd.conf

# Restart auditd
systemctl enable auditd
systemctl restart auditd

echo -e "${GREEN}  ✓ Auditd configured - all commands will be logged${NC}"

# ============================================================================
# STEP 3: Install Suricata for network monitoring
# ============================================================================
echo -e "${BLUE}[3/8] Installing Suricata for network capture...${NC}"

add-apt-repository -y ppa:oisf/suricata-stable
apt-get update -qq
apt-get install -y -qq suricata

# Configure Suricata
INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')

cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[$VM_IP/32, 192.168.40.0/24]"
    EXTERNAL_NET: "!\$HOME_NET"

default-log-dir: /var/log/suricata/

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http:
            extended: yes
        - dns
        - tls:
            extended: yes
        - files:
            force-magic: yes
            force-hash: [sha256]
        - flow
        - netflow

  # Capture files (malware downloads)
  - file-store:
      enabled: yes
      dir: /var/log/suricata/files
      force-magic: yes
      force-hash: [sha256]
      stream-depth: 0

af-packet:
  - interface: $INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

pcap-file:
  checksum-checks: auto

# Enable file extraction
file-store:
  enabled: yes

app-layer:
  protocols:
    http:
      enabled: yes
    tls:
      enabled: yes
    ssh:
      enabled: yes
    dns:
      enabled: yes
    ftp:
      enabled: yes
EOF

# Update Suricata rules
suricata-update

# Enable and start
systemctl enable suricata
systemctl restart suricata

echo -e "${GREEN}  ✓ Suricata installed - network traffic will be captured${NC}"

# ============================================================================
# STEP 4: Enable PCAP capture for full packet analysis
# ============================================================================
echo -e "${BLUE}[4/8] Setting up PCAP capture...${NC}"

mkdir -p /var/log/honeypot-pcap

cat > /etc/systemd/system/honeypot-pcap.service << EOF
[Unit]
Description=Honeypot PCAP Capture
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/tcpdump -i $INTERFACE -w /var/log/honeypot-pcap/capture-%%Y%%m%%d-%%H%%M%%S.pcap -G 3600 -Z root
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable honeypot-pcap
systemctl start honeypot-pcap

echo -e "${GREEN}  ✓ PCAP capture enabled - hourly rotation${NC}"

# ============================================================================
# STEP 5: Install Filebeat to ship logs
# ============================================================================
echo -e "${BLUE}[5/8] Installing Filebeat...${NC}"

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic.list

apt-get update -qq
apt-get install -y -qq filebeat

# Configure Filebeat
cat > /etc/filebeat/filebeat.yml << EOF
filebeat.inputs:

  # Auditd logs (all commands executed)
  - type: filestream
    id: auditd
    enabled: true
    paths:
      - /var/log/audit/audit.log
    fields:
      log_type: auditd
      honeypot_type: sacrificial-vm
      honeypot_ip: $VM_IP
    fields_under_root: true
    parsers:
      - multiline:
          pattern: '^type='
          negate: true
          match: after

  # Suricata EVE JSON (network events)
  - type: filestream
    id: suricata
    enabled: true
    paths:
      - /var/log/suricata/eve.json
    fields:
      log_type: suricata
      honeypot_type: sacrificial-vm
      honeypot_ip: $VM_IP
    fields_under_root: true
    parsers:
      - ndjson:
          keys_under_root: true
          add_error_key: true

  # Auth log (SSH logins)
  - type: filestream
    id: auth
    enabled: true
    paths:
      - /var/log/auth.log
    fields:
      log_type: auth
      honeypot_type: sacrificial-vm
      honeypot_ip: $VM_IP
    fields_under_root: true

  # Syslog
  - type: filestream
    id: syslog
    enabled: true
    paths:
      - /var/log/syslog
    fields:
      log_type: syslog
      honeypot_type: sacrificial-vm
    fields_under_root: true

processors:
  - add_host_metadata: ~
  - add_fields:
      target: ''
      fields:
        observer.type: honeypot
        observer.product: sacrificial-vm
        event.dataset: honeypot.sacrificial

output.elasticsearch:
  hosts: ["$ELASTICSEARCH_HOST"]
  index: "honeypot-sacrificial-%{+yyyy.MM.dd}"

setup.template.name: "honeypot-sacrificial"
setup.template.pattern: "honeypot-sacrificial-*"
setup.ilm.enabled: false
EOF

systemctl enable filebeat
systemctl restart filebeat

echo -e "${GREEN}  ✓ Filebeat installed - logs shipping to $ELASTICSEARCH_HOST${NC}"

# ============================================================================
# STEP 6: Make it look like a real dev server
# ============================================================================
echo -e "${BLUE}[6/8] Making VM look realistic...${NC}"

# Install common packages attackers expect
apt-get install -y -qq \
    nginx \
    mysql-server \
    python3 python3-pip \
    git curl wget \
    net-tools \
    htop \
    vim

# Create fake project directories
mkdir -p /var/www/html /opt/app /home/developer/projects

# Fake web app
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Internal Dev Server</title></head>
<body>
<h1>Development Server</h1>
<p>For internal use only.</p>
</body>
</html>
EOF

# Fake credentials file (bait)
cat > /home/developer/.env << 'EOF'
# Database credentials - DO NOT COMMIT
DB_HOST=db.internal.corp
DB_USER=app_user
DB_PASS=Pr0d_Passw0rd_2024!
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF
chmod 600 /home/developer/.env

# Fake SSH keys (bait)
mkdir -p /home/developer/.ssh
ssh-keygen -t rsa -b 2048 -f /home/developer/.ssh/id_rsa -N "" -q
cat > /home/developer/.ssh/config << 'EOF'
Host prod-db
    HostName 10.0.1.50
    User deploy
    IdentityFile ~/.ssh/id_rsa

Host prod-web
    HostName 10.0.1.51
    User deploy
    IdentityFile ~/.ssh/id_rsa
EOF

# Fake bash history (looks like real activity)
cat > /home/developer/.bash_history << 'EOF'
cd /opt/app
git pull origin main
docker-compose up -d
curl localhost:8080/health
mysql -u root -p
vim /etc/nginx/sites-available/app.conf
sudo systemctl restart nginx
tail -f /var/log/nginx/error.log
ssh prod-db
scp backup.sql prod-db:/tmp/
EOF

# Fake crontab
echo "0 2 * * * /opt/app/backup.sh" | crontab -u developer -

echo -e "${GREEN}  ✓ VM looks like a dev server with juicy bait files${NC}"

# ============================================================================
# STEP 7: Create snapshot script
# ============================================================================
echo -e "${BLUE}[7/8] Creating reset/snapshot script...${NC}"

cat > /root/honeypot-reset.sh << 'EOF'
#!/bin/bash
# Reset the honeypot after a compromise
# Run this to clean up and restore to baseline

echo "[*] Killing attacker processes..."
pkill -u developer 2>/dev/null
pkill -u admin 2>/dev/null

echo "[*] Cleaning /tmp and /var/tmp..."
rm -rf /tmp/* /var/tmp/*

echo "[*] Resetting user passwords..."
echo "root:root" | chpasswd
echo "admin:admin" | chpasswd
echo "developer:developer" | chpasswd

echo "[*] Clearing bash histories..."
> /root/.bash_history
> /home/developer/.bash_history
> /home/admin/.bash_history

echo "[*] Restarting services..."
systemctl restart sshd
systemctl restart nginx

echo "[*] Honeypot reset complete"
EOF
chmod +x /root/honeypot-reset.sh

echo -e "${GREEN}  ✓ Reset script created at /root/honeypot-reset.sh${NC}"

# ============================================================================
# STEP 8: Hide monitoring from attackers
# ============================================================================
echo -e "${BLUE}[8/8] Hiding monitoring from attackers...${NC}"

# Make audit processes less visible
# (Advanced attackers might still find them, but script kiddies won't)

# Hide Suricata in process list (rename binary)
# Note: This is security through obscurity - advanced attackers will find it
if [ -f /usr/bin/suricata ]; then
    cp /usr/bin/suricata /usr/bin/sysmon-daemon 2>/dev/null || true
fi

# Don't log monitoring services to syslog (reduces noise, hides them)
cat >> /etc/rsyslog.d/50-honeypot.conf << 'EOF'
# Hide monitoring logs from attackers viewing syslog
:programname, isequal, "suricata" stop
:programname, isequal, "filebeat" stop
:programname, isequal, "auditd" stop
EOF
systemctl restart rsyslog

echo -e "${GREEN}  ✓ Monitoring hidden from casual inspection${NC}"

# ============================================================================
# DONE
# ============================================================================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Sacrificial VM Setup Complete!                             ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "VM Configuration:"
echo "  IP Address:     $VM_IP"
echo "  SSH Port:       22"
echo "  Weak Creds:     root:root, admin:admin, developer:developer"
echo ""
echo "Monitoring Active:"
echo "  Auditd:         All commands logged to /var/log/audit/audit.log"
echo "  Suricata:       Network traffic to /var/log/suricata/eve.json"
echo "  PCAP:           Full capture to /var/log/honeypot-pcap/"
echo "  Filebeat:       Shipping to $ELASTICSEARCH_HOST"
echo ""
echo "Bait Files:"
echo "  /home/developer/.env       (fake AWS/DB creds)"
echo "  /home/developer/.ssh/      (fake SSH keys)"
echo ""
echo "Next Steps:"
echo "  1. Configure Cowrie to proxy to this VM (see cowrie-proxy.cfg)"
echo "  2. Take a VM snapshot now (for easy reset)"
echo "  3. Monitor in Grafana"
echo ""
echo "Reset after compromise:"
echo "  /root/honeypot-reset.sh"
echo ""
