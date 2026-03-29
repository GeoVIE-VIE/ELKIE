#!/bin/bash
###############################################################################
# setup_lab_vm.sh — Create Cisco Lab VM on Proxmox (VLAN 30)
#
# Run from ELK (192.168.50.3) to provision the VM via Proxmox API.
# After creation, SSH to the VM and run setup_jumpbox.sh for GNS3 + labctl.
#
# VM Details:
#   IP:    192.168.30.10
#   VLAN:  30
#   User:  labadmin
#   VMID:  110
###############################################################################

set -euo pipefail

PROXMOX_HOST="https://192.168.99.160:8006"
PROXMOX_TOKEN="${PVE_API_TOKEN:?Set PVE_API_TOKEN env var}"
NODE="flexiserve"
VMID=110
VM_NAME="cisco-lab"
VLAN=30
CORES=8
MEMORY=32768    # 32GB — GNS3 devices need RAM (Nexus alone is 6GB each)
DISK_SIZE="100G"
STORAGE="local-lvm"

# Ubuntu 22.04 cloud image — download to Proxmox if not present
ISO_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
ISO_NAME="jammy-server-cloudimg-amd64.img"

header() { echo -e "\n\033[1;36m=== $1 ===\033[0m"; }

api() {
    local method="$1" endpoint="$2"
    shift 2
    curl -sk -X "$method" \
        -H "Authorization: $PROXMOX_TOKEN" \
        "$PROXMOX_HOST/api2/json$endpoint" "$@"
}

# --- Preflight checks ---
header "Checking if VMID $VMID already exists"
EXISTS=$(api GET "/nodes/$NODE/qemu/$VMID/status/current" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('vmid',''))" 2>/dev/null || echo "")
if [ "$EXISTS" = "$VMID" ]; then
    echo "VM $VMID already exists. Delete it first or pick a different VMID."
    exit 1
fi
echo "VMID $VMID is available."

# --- Download cloud image to Proxmox ---
header "Downloading Ubuntu cloud image (if needed)"
echo "SSH to Proxmox to download image..."
echo "Run on Proxmox manually if this step fails:"
echo "  wget -P /var/lib/vz/template/iso/ $ISO_URL"
echo ""
echo "Then import disk:"
echo "  qm create $VMID --name $VM_NAME --memory $MEMORY --cores $CORES --net0 virtio,bridge=vmbr0,tag=$VLAN"
echo "  qm importdisk $VMID /var/lib/vz/template/iso/$ISO_NAME $STORAGE"
echo "  qm set $VMID --scsihw virtio-scsi-pci --scsi0 $STORAGE:vm-$VMID-disk-0"
echo "  qm set $VMID --ide2 $STORAGE:cloudinit"
echo "  qm set $VMID --boot c --bootdisk scsi0"
echo "  qm set $VMID --serial0 socket --vga serial0"
echo "  qm set $VMID --agent enabled=1"
echo "  qm resize $VMID scsi0 $DISK_SIZE"
echo ""

# --- Create VM via API ---
header "Creating VM $VMID ($VM_NAME)"
api POST "/nodes/$NODE/qemu" \
    -d "vmid=$VMID" \
    -d "name=$VM_NAME" \
    -d "memory=$MEMORY" \
    -d "cores=$CORES" \
    -d "sockets=1" \
    -d "cpu=host" \
    -d "net0=virtio=auto,bridge=vmbr$VLAN,firewall=1" \
    -d "scsihw=virtio-scsi-pci" \
    -d "ostype=l26" \
    -d "numa=1" \
    -d "onboot=1" \
    -d "start=0" | python3 -m json.tool 2>/dev/null || echo "(API response above)"

echo ""
echo "VM $VMID created. Now on Proxmox node, run:"
echo ""
echo "  # Download image"
echo "  cd /var/lib/vz/template/iso/"
echo "  wget $ISO_URL"
echo ""
echo "  # Import disk and configure cloud-init"
echo "  qm importdisk $VMID /var/lib/vz/template/iso/$ISO_NAME $STORAGE"
echo "  qm set $VMID --scsi0 $STORAGE:vm-$VMID-disk-0"
echo "  qm set $VMID --ide2 $STORAGE:cloudinit"
echo "  qm set $VMID --boot c --bootdisk scsi0"
echo "  qm set $VMID --serial0 socket --vga serial0"
echo "  qm set $VMID --agent enabled=1"
echo "  qm set $VMID --ipconfig0 ip=192.168.30.10/24,gw=192.168.30.1"
echo "  qm set $VMID --ciuser labadmin"
echo "  qm set $VMID --sshkeys /path/to/authorized_keys.pub"
echo "  qm resize $VMID scsi0 $DISK_SIZE"
echo "  qm set $VMID --cpu host   # nested virt for GNS3 QEMU"
echo ""
echo "  # Enable nested virtualization (if not already)"
echo "  echo 'options kvm_intel nested=1' > /etc/modprobe.d/kvm-nested.conf"
echo "  modprobe -r kvm_intel && modprobe kvm_intel"
echo ""
echo "  # Start the VM"
echo "  qm start $VMID"
echo ""

header "Post-boot steps"
echo "1. SSH to 192.168.30.10 as labadmin"
echo "2. Copy setup_jumpbox.sh to the VM"
echo "3. Run: sudo bash setup_jumpbox.sh"
echo "4. Copy Cisco images to /opt/cisco-lab/images/"
echo "5. Add pfSense rules (see below)"
echo ""

echo "Done. Set up pfSense rules to isolate this VM as needed."
