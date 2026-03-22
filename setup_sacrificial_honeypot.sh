#!/bin/bash
# Setup script for sacrificial VM honeypot authentication
# Run this on the sacrificial VM (192.168.40.99 / ReverseCowrie)

set -e

echo "=== Setting up Honeypot PAM Auth ==="

# Create directories
mkdir -p /etc/honeypot /var/lib/honeypot /var/log/honeypot
chmod 755 /etc/honeypot /var/log/honeypot
chmod 700 /var/lib/honeypot

# Install PAM script
cp /tmp/honeypot_pam.py /usr/local/bin/honeypot_pam.py
chmod 755 /usr/local/bin/honeypot_pam.py

# Create credential config
cat > /etc/honeypot/credentials.conf << 'CREDS'
# Format: username:password (one per line)
# These are the only credentials that will be accepted
root:root
root:toor
root:password
root:123456
root:admin
root:P@ssw0rd
root:letmein
root:changeme
root:qwerty
root:abc123
admin:admin
admin:password
admin:admin123
admin:1234
ubuntu:ubuntu
ubuntu:password
deploy:deploy
deploy:deploy123
test:test
test:test123
test:password
user:user
user:user123
user:password
pi:raspberry
pi:pi
oracle:oracle
oracle:password
ftpuser:ftpuser
ftpuser:ftp123
www-data:www-data
postgres:postgres
postgres:pgadmin
mysql:mysql
mysql:root
git:git
CREDS

# Create all the user accounts (so they exist on the real system)
for user in root admin ubuntu deploy test user pi oracle ftpuser postgres mysql git; do
    id "$user" &>/dev/null || useradd -m -s /bin/bash "$user" 2>/dev/null || true
done

# Set a random complex password for root (real password doesn't matter — PAM handles auth)
echo "root:$(openssl rand -base64 32)" | chpasswd 2>/dev/null

# Configure PAM to use our script
# Backup original
cp /etc/pam.d/sshd /etc/pam.d/sshd.bak

# Insert our PAM module BEFORE the standard auth
cat > /etc/pam.d/sshd << 'PAM'
# Honeypot PAM — custom auth handler
auth    [success=done default=die]    pam_exec.so expose_authtok /usr/local/bin/honeypot_pam.py
auth    required    pam_deny.so

# Standard account/session handling
account    required     pam_nologin.so
account    include      common-account
session    [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
session    include      common-session
session    optional     pam_motd.so motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv
session    required     pam_limits.so
session    [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open
PAM

# Configure sshd for honeypot
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cat > /etc/ssh/sshd_config << 'SSHD'
Port 22
ListenAddress 0.0.0.0
PermitRootLogin yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd yes
AcceptEnv LANG LC_*
MaxAuthTries 10
MaxSessions 5
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
# Log everything
LogLevel VERBOSE
SyslogFacility AUTH
SSHD

# Configure Filebeat to ship honeypot auth logs
cat > /etc/filebeat/inputs.d/honeypot-auth.yml << 'FB'
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/auth.json
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    log_type: honeypot_auth
  fields_under_root: true
FB

# Restart services
systemctl restart sshd
systemctl restart filebeat 2>/dev/null || true

echo "=== Honeypot PAM Auth Setup Complete ==="
echo "Credentials: /etc/honeypot/credentials.conf"
echo "Auth log: /var/log/honeypot/auth.json"
echo "State: /var/lib/honeypot/auth_state.json"
echo "PAM config: /etc/pam.d/sshd"
