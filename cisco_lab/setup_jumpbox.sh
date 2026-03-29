#!/bin/bash
###############################################################################
# setup_jumpbox.sh — Install GNS3 server + labctl on the Cisco Lab VM
#
# Run as root on 192.168.30.10 after Proxmox VM is provisioned.
# Installs: GNS3 server, QEMU/KVM, Docker, Python deps, labctl CLI
###############################################################################

set -euo pipefail

LAB_DIR="/opt/cisco-lab"
IMAGE_DIR="$LAB_DIR/images"
GNS3_PORT=3080
GNS3_USER="gns3"

header() { echo -e "\n\033[1;36m=== $1 ===\033[0m"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash setup_jumpbox.sh"
    exit 1
fi

# --- System packages ---
header "Installing system packages"
apt-get update
apt-get install -y \
    qemu-system-x86 qemu-utils \
    libvirt-daemon-system libvirt-clients \
    bridge-utils \
    docker.io docker-compose \
    python3 python3-pip python3-venv \
    telnet \
    jq \
    net-tools \
    openssh-server \
    git \
    tmux \
    figlet

# Enable nested virt check
if ! grep -q 'Y' /sys/module/kvm_intel/parameters/nested 2>/dev/null; then
    echo "WARNING: Nested virtualization not enabled. GNS3 QEMU devices will be slow."
    echo "On Proxmox host run:"
    echo "  echo 'options kvm_intel nested=1' > /etc/modprobe.d/kvm-nested.conf"
    echo "  modprobe -r kvm_intel && modprobe kvm_intel"
fi

# --- GNS3 server ---
header "Installing GNS3 server"
pip3 install gns3-server

# --- Directory structure ---
header "Setting up lab directories"
mkdir -p "$IMAGE_DIR"
mkdir -p "$LAB_DIR/projects"
mkdir -p "$LAB_DIR/configs"
mkdir -p /etc/cisco-lab

# --- GNS3 server config ---
header "Configuring GNS3 server"
mkdir -p /root/.config/GNS3/2.2
cat > /root/.config/GNS3/2.2/gns3_server.conf <<EOF
[Server]
host = 127.0.0.1
port = $GNS3_PORT
images_path = $IMAGE_DIR
projects_path = $LAB_DIR/projects
auth = False
allow_remote_console = True

[Qemu]
enable_hardware_acceleration = True
require_hardware_acceleration = False
EOF

# --- GNS3 systemd service ---
header "Creating GNS3 systemd service"
cat > /etc/systemd/system/gns3-server.service <<EOF
[Unit]
Description=GNS3 Server
After=network.target libvirtd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/gns3server --config /root/.config/GNS3/2.2/gns3_server.conf
Restart=on-failure
RestartSec=5
User=root
WorkingDirectory=$LAB_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable gns3-server
systemctl start gns3-server

# --- Install labctl ---
header "Installing labctl"
cp /tmp/lab_manager.py "$LAB_DIR/lab_manager.py" 2>/dev/null || echo "Copy lab_manager.py to $LAB_DIR/ manually"
cp /tmp/labctl "$LAB_DIR/labctl" 2>/dev/null || echo "Copy labctl to $LAB_DIR/ manually"

# Symlink to PATH
ln -sf "$LAB_DIR/labctl" /usr/local/bin/labctl
chmod +x "$LAB_DIR/labctl" 2>/dev/null || true

# --- Lab config file ---
header "Creating lab config"
cat > /etc/cisco-lab/config.json <<EOF
{
    "gns3_host": "127.0.0.1",
    "gns3_port": $GNS3_PORT,
    "image_dir": "$IMAGE_DIR/QEMU",
    "project_name": "cisco-lab",
    "device_templates": {
        "router": {
            "description": "Cisco IOSv Router",
            "image": "vios-adventerprisek9-m.spa.159-3.m6.qcow2",
            "ram": 512,
            "adapters": 4,
            "adapter_type": "e1000",
            "console_type": "telnet",
            "category": "router",
            "symbol": ":/symbols/router.svg",
            "options": "-nographic"
        },
        "switch": {
            "description": "Cisco IOSvL2 Switch",
            "image": "vios_l2-adventerprisek9-m.ssa.high_iron_20200929.qcow2",
            "ram": 768,
            "adapters": 16,
            "adapter_type": "e1000",
            "console_type": "telnet",
            "category": "switch",
            "symbol": ":/symbols/ethernet_switch.svg",
            "options": "-nographic"
        },
        "firewall": {
            "description": "Cisco ASAv Firewall",
            "image": "asav9-18-2.qcow2",
            "ram": 2048,
            "adapters": 8,
            "adapter_type": "e1000",
            "console_type": "telnet",
            "category": "firewall",
            "symbol": ":/symbols/firewall.svg",
            "options": "-nographic"
        },
        "csr": {
            "description": "Cisco CSR1000v (IOS-XE)",
            "image": "csr1000v-universalk9.17.03.08a-serial.qcow2",
            "ram": 3072,
            "adapters": 4,
            "adapter_type": "virtio-net-pci",
            "console_type": "telnet",
            "category": "router",
            "symbol": ":/symbols/router.svg",
            "options": "-nographic"
        },
        "nxos": {
            "description": "Cisco NX-OSv 9000",
            "image": "nexus9300v64-lite.10.5.5.M.qcow2",
            "ram": 6144,
            "adapters": 10,
            "adapter_type": "e1000",
            "console_type": "telnet",
            "category": "switch",
            "symbol": ":/symbols/multilayer_switch.svg",
            "options": "-nographic"
        }
    }
}
EOF

# --- MOTD ---
header "Setting login banner"
cat > /etc/update-motd.d/99-cisco-lab <<'MOTD'
#!/bin/bash
figlet -f slant "Cisco Lab" 2>/dev/null || echo "=== CISCO LAB ==="
echo ""
echo "  Commands:"
echo "    labctl status              — Show all devices and links"
echo "    labctl add <name> <type>   — Spin up a device (router, switch, firewall, csr, nxos)"
echo "    labctl remove <name>       — Destroy a device"
echo "    labctl connect <A> <intA> <B> <intB>  — Cable two devices"
echo "    labctl disconnect <A> <intA> <B> <intB> — Remove a cable"
echo "    labctl console <name>      — Console into a device"
echo "    labctl start <name>        — Boot a device"
echo "    labctl stop <name>         — Shut down a device"
echo "    labctl images              — List available images"
echo "    labctl topology            — Show ASCII topology map"
echo "    labctl save                — Save all running configs"
echo "    labctl wipe                — Destroy entire lab (confirmation required)"
echo ""
echo "  Images: /opt/cisco-lab/images/"
echo ""
MOTD
chmod +x /etc/update-motd.d/99-cisco-lab

# --- Create lab users group ---
header "Setting up lab users group"
groupadd -f labusers
echo "Add users with: useradd -m -G labusers -s /bin/bash <username>"

# --- Permissions ---
header "Setting permissions"
chmod -R 775 "$LAB_DIR"
chgrp -R labusers "$LAB_DIR"

header "Setup complete"
echo ""
echo "Next steps:"
echo "  1. Copy Cisco QCOW2 images to $IMAGE_DIR/"
echo "  2. Copy lab_manager.py to $LAB_DIR/"
echo "  3. Copy labctl to $LAB_DIR/ and run: chmod +x $LAB_DIR/labctl"
echo "  4. Create user accounts: useradd -m -G labusers -s /bin/bash <friend>"
echo "  5. Verify GNS3: curl http://127.0.0.1:$GNS3_PORT/v2/version"
echo "  6. Test: labctl add R1 router"
echo ""
echo "Supported image filenames (place in $IMAGE_DIR/):"
echo "  router:   vios-adventerprisek9-m.spa.159-3.m6.qcow2"
echo "  switch:   vios_l2-adventerprisek9-m.ssa.high_iron_20200929.qcow2"
echo "  firewall: asav9-18-2.qcow2"
echo "  csr:      csr1000v-universalk9.17.03.08a-serial.qcow2"
echo "  nxos:     nexus9300v64-lite.10.5.5.M.qcow2"
echo ""
echo "Image names can be changed in /etc/cisco-lab/config.json"
