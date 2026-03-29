#!/usr/bin/env python3
"""
lab_monitor.py — Idle Device Monitor + Live Topology Watcher

Tracks console activity on devices, auto-shuts down idle devices,
and provides a live-updating topology display.
"""

import json
import os
import sys
import time
import signal
import subprocess

MONITOR_STATE = "/opt/cisco-lab/monitor_state.json"
IDLE_TIMEOUT = 1800  # 30 minutes default


class IdleMonitor:
    """Track and auto-shutdown idle lab devices."""

    def __init__(self, lab_manager, timeout=IDLE_TIMEOUT):
        self.lab = lab_manager
        self.timeout = timeout
        self.state = self._load_state()

    def _load_state(self):
        if os.path.exists(MONITOR_STATE):
            try:
                with open(MONITOR_STATE) as f:
                    data = json.load(f)
                    if data:
                        return data
            except (json.JSONDecodeError, ValueError):
                pass
        return {"devices": {}, "auto_shutdown": True}

    def _save_state(self):
        with open(MONITOR_STATE, "w") as f:
            json.dump(self.state, f, indent=2)

    def update_activity(self, device_name):
        """Mark a device as recently active."""
        self.state.setdefault("devices", {})[device_name] = {
            "last_active": time.time(),
            "started_at": self.state.get("devices", {}).get(device_name, {}).get("started_at", time.time()),
        }
        self._save_state()

    def check_idle(self):
        """Check for idle devices and shut them down."""
        nodes = self.lab._get_nodes()
        now = time.time()
        shutdown_list = []

        for node in nodes:
            if node["status"] != "started":
                continue

            name = node["name"]
            device_state = self.state.get("devices", {}).get(name, {})
            last_active = device_state.get("last_active", now)

            idle_seconds = now - last_active
            if idle_seconds > self.timeout:
                shutdown_list.append((name, idle_seconds))

        return shutdown_list

    def auto_shutdown(self):
        """Shut down idle devices."""
        idle = self.check_idle()
        if not idle:
            return []

        shutdown = []
        for name, idle_time in idle:
            mins = int(idle_time / 60)
            try:
                self.lab.stop_device(name)
                print(f"  Auto-shutdown: {name} (idle {mins}m)")
                shutdown.append(name)
                # Remove from tracking
                self.state.get("devices", {}).pop(name, None)
            except Exception as e:
                print(f"  Failed to stop {name}: {e}")

        self._save_state()
        return shutdown

    def status(self):
        """Show device activity status."""
        nodes = self.lab._get_nodes()
        now = time.time()

        if not nodes:
            print("No devices.")
            return

        print(f"\n{'Device':<16} {'Status':<10} {'Uptime':<12} {'Idle':<12} {'Action'}")
        print("─" * 65)

        for node in sorted(nodes, key=lambda n: n["name"]):
            name = node["name"]
            status = node["status"]

            if status != "started":
                print(f"{name:<16} {'stopped':<10} {'—':<12} {'—':<12} —")
                continue

            device_state = self.state.get("devices", {}).get(name, {})
            started = device_state.get("started_at", now)
            last_active = device_state.get("last_active", now)

            uptime = self._format_duration(now - started)
            idle = self._format_duration(now - last_active)

            remaining = self.timeout - (now - last_active)
            if remaining <= 0:
                action = "WILL SHUTDOWN"
            elif remaining < 300:
                action = f"shutdown in {int(remaining/60)}m"
            else:
                action = "ok"

            print(f"{name:<16} {'running':<10} {uptime:<12} {idle:<12} {action}")

        print(f"\nIdle timeout: {self.timeout // 60} minutes")
        auto = "enabled" if self.state.get("auto_shutdown", True) else "disabled"
        print(f"Auto-shutdown: {auto}")

    def _format_duration(self, seconds):
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds/60)}m"
        else:
            h = int(seconds / 3600)
            m = int((seconds % 3600) / 60)
            return f"{h}h{m}m"

    def set_timeout(self, minutes):
        """Set idle timeout in minutes."""
        self.timeout = minutes * 60
        self.state["timeout"] = self.timeout
        self._save_state()
        print(f"Idle timeout set to {minutes} minutes.")

    def toggle_auto(self):
        """Toggle auto-shutdown."""
        current = self.state.get("auto_shutdown", True)
        self.state["auto_shutdown"] = not current
        self._save_state()
        status = "enabled" if not current else "disabled"
        print(f"Auto-shutdown {status}.")


def live_topology(lab_manager, interval=5):
    """Live-updating topology display."""

    def handler(signum, frame):
        print("\n\nExiting topology view.")
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)

    while True:
        # Clear screen
        os.system("clear")

        nodes = lab_manager._get_nodes()
        links = lab_manager._get_links()

        print("╔══════════════════════════════════════════════════════════╗")
        print("║           CISCO LAB — LIVE TOPOLOGY                    ║")
        print("║           Press Ctrl+C to exit                         ║")
        print("╚══════════════════════════════════════════════════════════╝")

        if not nodes:
            print("\n  No devices. Add some with: labctl add <name> <type>")
        else:
            # Build adjacency
            node_map = {n["node_id"]: n for n in nodes}
            adjacency = {n["name"]: [] for n in nodes}

            for link in links:
                ln = link["nodes"]
                if len(ln) == 2:
                    a = node_map.get(ln[0]["node_id"])
                    b = node_map.get(ln[1]["node_id"])
                    if a and b:
                        a_if = f"gi{ln[0]['adapter_number']}/{ln[0]['port_number']}"
                        b_if = f"gi{ln[1]['adapter_number']}/{ln[1]['port_number']}"
                        adjacency[a["name"]].append((b["name"], a_if, b_if))
                        adjacency[b["name"]].append((a["name"], b_if, a_if))

            print("")
            visited_links = set()

            for node in sorted(nodes, key=lambda n: n["name"]):
                name = node["name"]
                status = "UP" if node["status"] == "started" else "DOWN"
                console = node.get("console", "?")
                ram = node.get("properties", {}).get("ram", "?")

                color_start = "\033[92m" if status == "UP" else "\033[91m"
                color_end = "\033[0m"

                print(f"  {color_start}┌─────────────────────┐{color_end}")
                print(f"  {color_start}│ {name:<12} {status:>6} │{color_end}")
                print(f"  {color_start}│ console: {console:<10} │{color_end}")
                print(f"  {color_start}│ RAM: {ram}MB{' ' * (13 - len(str(ram)))}│{color_end}")
                print(f"  {color_start}└─────────────────────┘{color_end}")

                for neighbor, local_if, remote_if in adjacency.get(name, []):
                    link_key = tuple(sorted([f"{name}:{local_if}", f"{neighbor}:{remote_if}"]))
                    if link_key not in visited_links:
                        visited_links.add(link_key)
                        print(f"    └── {local_if} ═══════════ {remote_if} ── [{neighbor}]")
                print("")

        # Summary
        running = sum(1 for n in nodes if n["status"] == "started")
        stopped = sum(1 for n in nodes if n["status"] != "started")
        total_ram = sum(n.get("properties", {}).get("ram", 0) for n in nodes if n["status"] == "started")

        print(f"  Devices: {running} running, {stopped} stopped | Links: {len(links)}")
        print(f"  RAM in use: {total_ram}MB / 32768MB ({int(total_ram/327.68)}%)")
        print(f"\n  Updated: {time.strftime('%H:%M:%S')} | Refresh: {interval}s")

        time.sleep(interval)
