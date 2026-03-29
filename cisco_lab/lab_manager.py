#!/usr/bin/env python3
"""
lab_manager.py — GNS3 Lab Manager for Cisco Lab

Wraps the GNS3 REST API to provide simple device lifecycle management.
Used by the `labctl` CLI tool.
"""

import json
import os
import sys
import time
import subprocess
import urllib.request
import urllib.error
import urllib.parse

CONFIG_PATH = "/etc/cisco-lab/config.json"
STATE_PATH = "/opt/cisco-lab/lab_state.json"


class LabManager:
    def __init__(self):
        self.config = self._load_config()
        self.base_url = f"http://{self.config['gns3_host']}:{self.config['gns3_port']}/v3"
        self.token = None
        self._authenticate()
        self.project_id = None
        self._ensure_project()

    def _load_config(self):
        with open(CONFIG_PATH) as f:
            return json.load(f)

    def _authenticate(self):
        """Get JWT token from GNS3 server."""
        url = f"{self.base_url}/access/users/authenticate"
        creds = json.dumps({
            "username": self.config.get("gns3_user", "admin"),
            "password": self.config.get("gns3_pass", "admin"),
        }).encode()
        req = urllib.request.Request(url, data=creds, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                self.token = data.get("access_token")
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            raise RuntimeError(f"GNS3 authentication failed: {e}")

    def _api(self, method, endpoint, data=None):
        """Make a GNS3 API call."""
        url = f"{self.base_url}{endpoint}"
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode()
                if not body.strip():
                    return None
                try:
                    return json.loads(body)
                except json.JSONDecodeError:
                    return None
        except urllib.error.HTTPError as e:
            if e.code == 204:
                return None
            if e.code == 409:
                return None  # conflict (e.g., already started/stopped)
            error_body = e.read().decode()
            raise RuntimeError(f"GNS3 API error {e.code}: {error_body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Cannot reach GNS3 server: {e.reason}")

    def _ensure_project(self):
        """Get or create the lab project."""
        projects = self._api("GET", "/projects")
        for p in projects:
            if p["name"] == self.config["project_name"]:
                self.project_id = p["project_id"]
                if p["status"] != "opened":
                    self._api("POST", f"/projects/{self.project_id}/open", {})
                return

        result = self._api("POST", "/projects", {
            "name": self.config["project_name"],
            "auto_open": True,
            "auto_start": False,
        })
        self.project_id = result["project_id"]

    # --- Template management ---

    def _get_templates(self):
        """List all GNS3 templates."""
        return self._api("GET", "/templates")

    def _find_template(self, device_type):
        """Find or create a template for the given device type."""
        templates = self._get_templates()
        template_name = f"cisco-lab-{device_type}"

        for t in templates:
            if t["name"] == template_name:
                return t["template_id"]

        # Create template from config
        if device_type not in self.config["device_templates"]:
            raise ValueError(
                f"Unknown device type '{device_type}'. "
                f"Available: {', '.join(self.config['device_templates'].keys())}"
            )

        tpl = self.config["device_templates"][device_type]
        image_path = os.path.join(self.config["image_dir"], tpl["image"])

        if not os.path.exists(image_path):
            raise FileNotFoundError(
                f"Image not found: {image_path}\n"
                f"Download the image and place it in {self.config['image_dir']}/"
            )

        template_data = {
            "name": template_name,
            "compute_id": "local",
            "template_type": "qemu",
            "platform": "x86_64",
            "hda_disk_image": tpl["image"],
            "hda_disk_interface": tpl.get("disk_interface", "ide"),
            "ram": tpl["ram"],
            "adapters": tpl["adapters"],
            "adapter_type": tpl["adapter_type"],
            "console_type": tpl["console_type"],
            "category": tpl["category"],
            "symbol": tpl.get("symbol", ":/symbols/router.svg"),
            "qemu_path": "/usr/bin/qemu-system-x86_64",
            "usage": tpl["description"],
            "options": tpl.get("options", "-nographic"),
        }

        result = self._api("POST", "/templates", template_data)
        return result["template_id"]

    _node_type_cache = {}

    def _adapter_to_iface(self, node_id, adapter, port, nodes=None):
        """Convert GNS3 adapter/port numbers to IOS interface name.
        CSR1000v: adapter 0 = Gi1 (1-indexed, no slot)
        IOSv/Nexus: adapter 0, port 0 = Gi0/0 (0-indexed, slot/port)
        """
        if node_id not in self._node_type_cache:
            if nodes is None:
                nodes = self._get_nodes()
            for n in nodes:
                adapter_type = n.get("properties", {}).get("adapter_type", "")
                self._node_type_cache[n["node_id"]] = "csr" if "virtio" in adapter_type else "ios"
        if self._node_type_cache.get(node_id) == "csr":
            return f"Gi{adapter + 1}"
        return f"Gi{adapter}/{port}"

    # --- Device management ---

    def _get_nodes(self):
        """Get all nodes in the project."""
        return self._api("GET", f"/projects/{self.project_id}/nodes")

    def _find_node(self, name):
        """Find a node by name."""
        for node in self._get_nodes():
            if node["name"] == name:
                return node
        return None

    def _get_links(self):
        """Get all links in the project."""
        return self._api("GET", f"/projects/{self.project_id}/links")

    def add_device(self, name, device_type):
        """Spin up a new device."""
        existing = self._find_node(name)
        if existing:
            raise ValueError(f"Device '{name}' already exists. Pick a different name.")

        template_id = self._find_template(device_type)

        # Auto-position: spread devices on the canvas
        nodes = self._get_nodes()
        x = (len(nodes) % 5) * 200 - 400
        y = (len(nodes) // 5) * 200 - 200

        result = self._api("POST", f"/projects/{self.project_id}/templates/{template_id}", {
            "x": x,
            "y": y,
            "name": name,
        })

        # GNS3 v3 ignores the name on template deploy — rename after creation
        if result.get("name") != name:
            result = self._api("PUT", f"/projects/{self.project_id}/nodes/{result['node_id']}", {
                "name": name,
            })

        print(f"Device '{name}' ({device_type}) created.")
        print(f"  Node ID:  {result['node_id']}")
        print(f"  Console:  telnet 127.0.0.1 {result.get('console', 'N/A')}")
        print(f"  Status:   {result['status']}")
        print(f"  RAM:      {self.config['device_templates'][device_type]['ram']}MB")
        print(f"\n  Start it: labctl start {name}")
        return result

    def remove_device(self, name):
        """Destroy a device and all its links."""
        node = self._find_node(name)
        if not node:
            raise ValueError(f"Device '{name}' not found.")

        if node["status"] == "started":
            self._api("POST", f"/projects/{self.project_id}/nodes/{node['node_id']}/stop", {})
            time.sleep(1)

        self._api("DELETE", f"/projects/{self.project_id}/nodes/{node['node_id']}")
        print(f"Device '{name}' destroyed.")

    def start_device(self, name):
        """Boot a device."""
        node = self._find_node(name)
        if not node:
            raise ValueError(f"Device '{name}' not found.")
        if node["status"] == "started":
            print(f"Device '{name}' is already running.")
            return

        self._api("POST", f"/projects/{self.project_id}/nodes/{node['node_id']}/start", {})
        print(f"Device '{name}' is booting...")
        print(f"  Console: labctl console {name}")

    def stop_device(self, name):
        """Shut down a device."""
        node = self._find_node(name)
        if not node:
            raise ValueError(f"Device '{name}' not found.")
        if node["status"] == "stopped":
            print(f"Device '{name}' is already stopped.")
            return

        self._api("POST", f"/projects/{self.project_id}/nodes/{node['node_id']}/stop", {})
        print(f"Device '{name}' stopped.")

    def start_all(self):
        """Start all devices."""
        nodes = self._get_nodes()
        for node in nodes:
            if node["status"] != "started":
                self._api("POST", f"/projects/{self.project_id}/nodes/{node['node_id']}/start", {})
                print(f"  Starting {node['name']}...")
        print("All devices starting.")

    def stop_all(self):
        """Stop all devices."""
        nodes = self._get_nodes()
        for node in nodes:
            if node["status"] == "started":
                self._api("POST", f"/projects/{self.project_id}/nodes/{node['node_id']}/stop", {})
                print(f"  Stopping {node['name']}...")
        print("All devices stopped.")

    # --- Linking ---

    def _parse_interface(self, node, iface_str):
        """
        Parse interface string into GNS3 adapter/port numbers.

        CSR1000v uses 1-indexed interfaces (GigabitEthernet1 = adapter 0):
          gi1   → adapter 0, port 0
          gi2   → adapter 1, port 0
          gi3   → adapter 2, port 0

        IOSv/IOSvL2 uses slot/port format (0-indexed):
          gi0/0 → adapter 0, port 0
          gi0/1 → adapter 0, port 1
          e0/1  → adapter 0, port 1
        """
        iface_str = iface_str.lower().strip()

        # Strip common prefixes
        for prefix in ["gigabitethernet", "gi", "fastethernet", "fa",
                       "ethernet", "eth", "e", "tengige", "te", "mg", "mgmt"]:
            if iface_str.startswith(prefix):
                iface_str = iface_str[len(prefix):]
                break

        parts = iface_str.split("/")
        if len(parts) == 2:
            # Slot/port format (gi0/0) — already 0-indexed
            adapter = int(parts[0])
            port = int(parts[1])
        elif len(parts) == 1:
            # Single number format (gi1, gi2) — 1-indexed on CSR1000v
            num = int(parts[0])
            if num >= 1:
                adapter = num - 1  # GigabitEthernet1 = adapter 0
            else:
                adapter = num
            port = 0
        else:
            raise ValueError(f"Cannot parse interface '{iface_str}'. Use format like gi1 or gi0/0")

        return adapter, port

    def connect(self, name_a, iface_a, name_b, iface_b):
        """Connect two devices."""
        node_a = self._find_node(name_a)
        node_b = self._find_node(name_b)
        if not node_a:
            raise ValueError(f"Device '{name_a}' not found.")
        if not node_b:
            raise ValueError(f"Device '{name_b}' not found.")

        adapter_a, port_a = self._parse_interface(node_a, iface_a)
        adapter_b, port_b = self._parse_interface(node_b, iface_b)

        link_data = {
            "nodes": [
                {
                    "node_id": node_a["node_id"],
                    "adapter_number": adapter_a,
                    "port_number": port_a,
                },
                {
                    "node_id": node_b["node_id"],
                    "adapter_number": adapter_b,
                    "port_number": port_b,
                },
            ]
        }

        result = self._api("POST", f"/projects/{self.project_id}/links", link_data)
        print(f"Connected: {name_a} {iface_a} <──> {name_b} {iface_b}")
        return result

    def disconnect(self, name_a, iface_a, name_b, iface_b):
        """Remove a link between two devices."""
        node_a = self._find_node(name_a)
        node_b = self._find_node(name_b)
        if not node_a or not node_b:
            raise ValueError("One or both devices not found.")

        adapter_a, port_a = self._parse_interface(node_a, iface_a)
        adapter_b, port_b = self._parse_interface(node_b, iface_b)

        links = self._get_links()
        for link in links:
            nodes = link["nodes"]
            if len(nodes) != 2:
                continue
            match = (
                (nodes[0]["node_id"] == node_a["node_id"] and
                 nodes[0]["adapter_number"] == adapter_a and
                 nodes[0]["port_number"] == port_a and
                 nodes[1]["node_id"] == node_b["node_id"] and
                 nodes[1]["adapter_number"] == adapter_b and
                 nodes[1]["port_number"] == port_b)
                or
                (nodes[1]["node_id"] == node_a["node_id"] and
                 nodes[1]["adapter_number"] == adapter_a and
                 nodes[1]["port_number"] == port_a and
                 nodes[0]["node_id"] == node_b["node_id"] and
                 nodes[0]["adapter_number"] == adapter_b and
                 nodes[0]["port_number"] == port_b)
            )
            if match:
                self._api("DELETE", f"/projects/{self.project_id}/links/{link['link_id']}")
                print(f"Disconnected: {name_a} {iface_a} <╌╌> {name_b} {iface_b}")
                return

        raise ValueError(f"No link found between {name_a} {iface_a} and {name_b} {iface_b}")

    # --- Console ---

    def console(self, name):
        """Open console to a device (drops into telnet)."""
        node = self._find_node(name)
        if not node:
            raise ValueError(f"Device '{name}' not found.")
        if node["status"] != "started":
            raise ValueError(f"Device '{name}' is not running. Start it first: labctl start {name}")

        port = node.get("console")
        if not port:
            raise ValueError(f"No console port assigned to '{name}'.")

        print(f"Connecting to {name} (telnet 127.0.0.1 {port})...")
        print("  Exit with: Ctrl+] then 'quit'")
        print("")
        os.execvp("telnet", ["telnet", "127.0.0.1", str(port)])

    # --- Status / Topology ---

    def status(self):
        """Show all devices and their status."""
        nodes = self._get_nodes()
        links = self._get_links()

        if not nodes:
            print("No devices in the lab. Add one with: labctl add <name> <type>")
            print(f"  Types: {', '.join(self.config['device_templates'].keys())}")
            return

        print(f"\n{'Name':<16} {'Type':<12} {'Status':<10} {'Console':<18} {'RAM':<8} {'Interfaces'}")
        print("─" * 85)

        for node in sorted(nodes, key=lambda n: n["name"]):
            name = node["name"]
            status = node["status"]
            console_port = node.get("console", "N/A")
            node_type = node.get("node_type", "qemu")
            ram = f"{node.get('properties', {}).get('ram', '?')}MB"

            # Count connected interfaces
            connected = 0
            for link in links:
                for ln in link["nodes"]:
                    if ln["node_id"] == node["node_id"]:
                        connected += 1

            total_adapters = node.get("properties", {}).get("adapters", "?")

            status_icon = "●" if status == "started" else "○"
            console_str = f"telnet 127.0.0.1 {console_port}" if console_port != "N/A" else "N/A"

            print(f"{status_icon} {name:<14} {node_type:<12} {status:<10} {console_str:<18} {ram:<8} {connected}/{total_adapters}")

        if links:
            print(f"\nLinks ({len(links)}):")
            node_map = {n["node_id"]: n["name"] for n in nodes}
            for link in links:
                ln = link["nodes"]
                if len(ln) == 2:
                    a_name = node_map.get(ln[0]["node_id"], "?")
                    b_name = node_map.get(ln[1]["node_id"], "?")
                    a_iface = self._adapter_to_iface(ln[0]["node_id"], ln[0]["adapter_number"], ln[0]["port_number"])
                    b_iface = self._adapter_to_iface(ln[1]["node_id"], ln[1]["adapter_number"], ln[1]["port_number"])
                    print(f"  {a_name} {a_iface} <──> {b_name} {b_iface}")

    def topology(self):
        """Show ASCII topology map."""
        nodes = self._get_nodes()
        links = self._get_links()

        if not nodes:
            print("Empty lab.")
            return

        node_map = {n["node_id"]: n["name"] for n in nodes}
        adjacency = {}
        for node in nodes:
            adjacency[node["name"]] = []

        for link in links:
            ln = link["nodes"]
            if len(ln) == 2:
                a = node_map.get(ln[0]["node_id"], "?")
                b = node_map.get(ln[1]["node_id"], "?")
                a_iface = self._adapter_to_iface(ln[0]["node_id"], ln[0]["adapter_number"], ln[0]["port_number"])
                b_iface = self._adapter_to_iface(ln[1]["node_id"], ln[1]["adapter_number"], ln[1]["port_number"])
                adjacency.setdefault(a, []).append((b, a_iface, b_iface))
                adjacency.setdefault(b, []).append((a, b_iface, a_iface))

        print("\n╔══════════════════════════════════════╗")
        print("║          CISCO LAB TOPOLOGY          ║")
        print("╚══════════════════════════════════════╝\n")

        visited = set()
        for name in sorted(adjacency.keys()):
            node = self._find_node(name)
            status = "UP" if node and node["status"] == "started" else "DOWN"
            box = f"[{name} ({status})]"
            print(f"  {box}")

            for neighbor, local_if, remote_if in adjacency[name]:
                link_key = tuple(sorted([f"{name}:{local_if}", f"{neighbor}:{remote_if}"]))
                if link_key not in visited:
                    visited.add(link_key)
                    print(f"    └── {local_if} ──────── {remote_if} ── [{neighbor}]")
            print("")

    # --- Images ---

    def list_images(self):
        """List available and expected images."""
        print(f"\nImage directory: {self.config['image_dir']}/\n")

        existing = set()
        if os.path.exists(self.config["image_dir"]):
            existing = set(os.listdir(self.config["image_dir"]))

        print(f"{'Type':<12} {'Image File':<55} {'Status'}")
        print("─" * 80)

        for dtype, tpl in self.config["device_templates"].items():
            img = tpl["image"]
            found = "✓ Found" if img in existing else "✗ Missing"
            print(f"{dtype:<12} {img:<55} {found}")

        # Show any extra files in image dir
        expected = {t["image"] for t in self.config["device_templates"].values()}
        extra = existing - expected
        if extra:
            print(f"\nOther files in image dir:")
            for f in sorted(extra):
                size = os.path.getsize(os.path.join(self.config["image_dir"], f))
                print(f"  {f} ({size // (1024*1024)}MB)")

    # --- Config save ---

    def save_configs(self):
        """Export startup configs from all running devices."""
        nodes = self._get_nodes()
        config_dir = "/opt/cisco-lab/configs"
        os.makedirs(config_dir, exist_ok=True)

        saved = 0
        for node in nodes:
            if node["status"] != "started":
                continue
            try:
                files = self._api("GET",
                    f"/projects/{self.project_id}/nodes/{node['node_id']}/files")
                for f in files:
                    if "startup-config" in f.get("path", ""):
                        content = self._api("GET",
                            f"/projects/{self.project_id}/nodes/{node['node_id']}/files/{f['path']}")
                        out_path = os.path.join(config_dir, f"{node['name']}-startup.cfg")
                        with open(out_path, "w") as fh:
                            fh.write(str(content))
                        print(f"  Saved: {out_path}")
                        saved += 1
            except Exception:
                # Not all node types support file listing
                pass

        if saved == 0:
            print("No configs to save (devices may not have startup configs yet).")
        else:
            print(f"\n{saved} config(s) saved to {config_dir}/")

    # --- Snapshots ---

    def _get_qemu_monitor_port(self, node):
        """Get the QEMU monitor TCP port for a node by reading the process cmdline."""
        import subprocess
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        node_id = node["node_id"]
        for line in result.stdout.split("\n"):
            if node_id in line and "monitor tcp:" in line:
                parts = line.split("monitor tcp:127.0.0.1:")
                if len(parts) > 1:
                    port = parts[1].split(",")[0]
                    return int(port)
        return None

    def _qemu_monitor_cmd(self, port, command, timeout=10):
        """Send a command to the QEMU monitor and return output."""
        import socket as sock
        s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("127.0.0.1", port))
        time.sleep(0.3)
        s.recv(4096)  # read banner
        s.sendall(command.encode() + b"\r\n")
        time.sleep(1)
        try:
            data = s.recv(8192).decode(errors="replace")
        except Exception:
            data = ""
        s.close()
        return data

    def vm_snapshot_create(self, snap_name="clean"):
        """Create a QEMU VM snapshot (savevm) on all running devices. Instant restore."""
        nodes = self._get_nodes()
        saved = 0
        for node in nodes:
            if node["status"] != "started":
                continue
            port = self._get_qemu_monitor_port(node)
            if not port:
                print(f"  {node['name']}: monitor port not found, skipping")
                continue
            self._qemu_monitor_cmd(port, f"savevm {snap_name}", timeout=30)
            print(f"  {node['name']}: VM state saved as '{snap_name}'")
            saved += 1
        if saved:
            print(f"Snapshot '{snap_name}' saved on {saved} device(s).")
        else:
            print("No running devices to snapshot.")

    def vm_snapshot_restore(self, snap_name="clean"):
        """Restore a QEMU VM snapshot (loadvm) on all running devices. Instant."""
        nodes = self._get_nodes()
        restored = 0
        for node in nodes:
            if node["status"] != "started":
                continue
            port = self._get_qemu_monitor_port(node)
            if not port:
                continue
            self._qemu_monitor_cmd(port, f"loadvm {snap_name}", timeout=30)
            print(f"  {node['name']}: VM state restored from '{snap_name}'")
            restored += 1
        if restored:
            print(f"Restored '{snap_name}' on {restored} device(s).")
        return restored > 0

    def vm_snapshot_list(self):
        """List QEMU VM snapshots on all running devices."""
        nodes = self._get_nodes()
        for node in nodes:
            if node["status"] != "started":
                continue
            port = self._get_qemu_monitor_port(node)
            if not port:
                continue
            data = self._qemu_monitor_cmd(port, "info snapshots")
            # Clean up QEMU echo garbage
            lines = [l for l in data.split("\n") if "ID" in l or "clean" in l or "snapshot" in l.lower()]
            print(f"  {node['name']}:")
            for l in lines:
                print(f"    {l.strip()}")
            if not lines:
                print(f"    (no snapshots)")

    def vm_snapshot_delete(self, snap_name="clean"):
        """Delete a QEMU VM snapshot."""
        nodes = self._get_nodes()
        for node in nodes:
            if node["status"] != "started":
                continue
            port = self._get_qemu_monitor_port(node)
            if not port:
                continue
            self._qemu_monitor_cmd(port, f"delvm {snap_name}")
            print(f"  {node['name']}: snapshot '{snap_name}' deleted")

    def snapshot_create(self, name="clean-boot"):
        """Create a project snapshot. Devices must be stopped first."""
        # Check if any devices are running
        nodes = self._get_nodes()
        running = [n for n in nodes if n["status"] == "started"]
        if running:
            print(f"Stopping {len(running)} device(s) for snapshot...")
            self.stop_all()
            time.sleep(3)

        result = self._api("POST", f"/projects/{self.project_id}/snapshots", {"name": name})
        if result:
            print(f"Snapshot '{name}' created.")

        # Restart devices
        if running:
            print("Restarting devices...")
            self.start_all()

        return result

    def snapshot_list(self):
        """List project snapshots."""
        snapshots = self._api("GET", f"/projects/{self.project_id}/snapshots") or []
        if not snapshots:
            print("No snapshots. Create one: labctl snapshot create")
            return snapshots
        print(f"\nSnapshots:")
        for s in snapshots:
            print(f"  {s['name']} — {s.get('created_at', '?')}")
        return snapshots

    def snapshot_restore(self, name="clean-boot"):
        """Restore a project snapshot. Returns True if successful."""
        snapshots = self._api("GET", f"/projects/{self.project_id}/snapshots") or []
        for s in snapshots:
            if s["name"] == name:
                self._api("POST", f"/projects/{self.project_id}/snapshots/{s['snapshot_id']}/restore", {})
                print(f"Snapshot '{name}' restored.")
                return True
        print(f"Snapshot '{name}' not found.")
        return False

    def snapshot_delete(self, name):
        """Delete a project snapshot."""
        snapshots = self._api("GET", f"/projects/{self.project_id}/snapshots") or []
        for s in snapshots:
            if s["name"] == name:
                self._api("DELETE", f"/projects/{self.project_id}/snapshots/{s['snapshot_id']}")
                print(f"Snapshot '{name}' deleted.")
                return True
        print(f"Snapshot '{name}' not found.")
        return False

    # --- Wipe ---

    def wipe(self, confirmed=False):
        """Destroy entire lab."""
        nodes = self._get_nodes()
        if not nodes:
            print("Lab is already empty.")
            return

        if not confirmed:
            print(f"This will destroy {len(nodes)} device(s) and all links.")
            print("Run: labctl wipe --confirm")
            return

        self.stop_all()
        time.sleep(2)

        for node in nodes:
            self._api("DELETE", f"/projects/{self.project_id}/nodes/{node['node_id']}")
            print(f"  Destroyed: {node['name']}")

        print("\nLab wiped clean.")

    # --- User management ---

    def add_user(self, username):
        """Create a lab user account."""
        try:
            subprocess.run(
                ["useradd", "-m", "-G", "labusers", "-s", "/bin/bash", username],
                check=True, capture_output=True, text=True
            )
            print(f"User '{username}' created.")
            print(f"  Set password: sudo passwd {username}")
            print(f"  Or add SSH key: ssh-copy-id {username}@192.168.30.10")
        except subprocess.CalledProcessError as e:
            if "already exists" in e.stderr:
                print(f"User '{username}' already exists.")
            else:
                raise

    def list_users(self):
        """List lab users."""
        try:
            import grp
            group = grp.getgrnam("labusers")
            members = group.gr_mem
            if members:
                print("Lab users:")
                for m in sorted(members):
                    print(f"  {m}")
            else:
                print("No lab users yet. Add one: labctl adduser <name>")
        except KeyError:
            print("Group 'labusers' doesn't exist. Run setup_jumpbox.sh first.")
