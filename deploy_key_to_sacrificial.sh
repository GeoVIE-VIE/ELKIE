#!/bin/bash
# Deploy SSH key and configure sacrificial VM (192.168.40.99)
# Run as: production user with sudo access

set -e

PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMhSd4pKVZmBbWfjX5LOUWC2/GwNy/opPbQaif3EbLEN legs@elk"

echo "=== Deploying SSH key to root ==="
sudo mkdir -p /root/.ssh
echo "$PUBKEY" | sudo tee -a /root/.ssh/authorized_keys > /dev/null
sudo chmod 700 /root/.ssh
sudo chmod 600 /root/.ssh/authorized_keys

echo "=== Setting root password ==="
echo "root:$ROOT_PASSWORD" | sudo chpasswd

echo "=== Ensuring SSH config allows root login ==="
sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

echo "=== Configuring NTP to use T-Pot (192.168.40.3) ==="
if command -v timedatectl &>/dev/null; then
    sudo timedatectl set-ntp off 2>/dev/null || true
fi
if [ -f /etc/systemd/timesyncd.conf ]; then
    sudo bash -c "cat > /etc/systemd/timesyncd.conf << 'EOF'
[Time]
NTP=192.168.40.3
FallbackNTP=192.168.40.3
EOF"
    sudo systemctl restart systemd-timesyncd 2>/dev/null || true
    sudo timedatectl set-ntp on 2>/dev/null || true
fi
# Also try chrony if installed
if command -v chronyc &>/dev/null; then
    sudo bash -c "echo 'server 192.168.40.3 iburst' > /etc/chrony/chrony.conf"
    sudo systemctl restart chrony 2>/dev/null || true
fi

echo "=== Restarting sshd ==="
sudo systemctl restart sshd

echo "=== Done ==="
echo "SSH key deployed, root password set, NTP pointed at 192.168.40.3"
echo "Test with: ssh root@192.168.40.99"
