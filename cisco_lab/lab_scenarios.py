#!/usr/bin/env python3
"""
lab_scenarios.py — Troubleshooting Scenario Engine for Cisco Lab

Generates and deploys broken topologies for users to diagnose and fix.
120 scenarios across 16 categories, with auto spinup/teardown and validation.
"""

import json
import os
import sys
import time
import random
import telnetlib
import re

SCENARIO_STATE_PATH = "/opt/cisco-lab/scenario_state.json"

# Telnet helper to push configs to devices
class DeviceConsole:
    """Interact with a device via its GNS3 telnet console."""

    def __init__(self, host="127.0.0.1", port=None, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tn = None

    def connect(self, retries=3):
        for attempt in range(retries):
            try:
                self.tn = telnetlib.Telnet(self.host, self.port, timeout=self.timeout)
                time.sleep(1)
                self.tn.write(b"\r\n")
                time.sleep(2)
                return True
            except Exception:
                time.sleep(3)
        return False

    def send(self, command, wait=1):
        if not self.tn:
            return ""
        self.tn.write(command.encode() + b"\r\n")
        time.sleep(wait)
        return self.tn.read_very_eager().decode(errors="ignore")

    def send_config(self, commands):
        """Send a list of commands in config mode."""
        self.send("enable", wait=2)
        self.send("", wait=1)  # handle any password prompt
        self.send("configure terminal", wait=1)
        self.send("no logging console", wait=0.5)
        for cmd in commands:
            self.send(cmd, wait=0.5)
        self.send("end", wait=1)
        self.send("write memory", wait=2)

    def get_output(self, command, wait=3):
        """Send a command and capture output."""
        self.send("", wait=0.5)
        self.send("terminal length 0", wait=1)
        self.tn.read_very_eager()  # clear buffer
        self.tn.write(command.encode() + b"\r\n")
        time.sleep(wait)
        return self.tn.read_very_eager().decode(errors="ignore")

    def close(self):
        if self.tn:
            self.tn.close()


# --- Scenario Definitions ---
# Each scenario defines:
#   - category: topic area
#   - difficulty: 1-5
#   - devices: list of (name, type) to spin up
#   - links: list of (deviceA, ifA, deviceB, ifB)
#   - base_config: dict of device_name -> [config commands] (working config)
#   - break_config: dict of device_name -> [config commands] (introduces the fault)
#   - description: what the user sees
#   - hint: optional hint
#   - validate: dict of device_name -> (command, expected_pattern) to check fix

SCENARIOS = [
    # ========== CATEGORY 1: INTERFACE / LAYER 1 (1-10) ==========
    {
        "id": 1,
        "name": "Shut Interface",
        "category": "Interface",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
            ],
        },
        "break_config": {"R1": ["interface gi1", "shutdown"]},
        "description": "R1 cannot ping R2 at 10.0.12.2. The link was working earlier today. Find and fix the issue.",
        "hint": "Check interface status on both sides.",
        "validate": {"R1": ("ping 10.0.12.2 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 2,
        "name": "Duplex Mismatch",
        "category": "Interface",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
            ],
        },
        "break_config": {"R1": ["interface gi1", "duplex half"]},
        "description": "Users report intermittent connectivity between R1 and R2. Pings sometimes work, sometimes fail. Investigate.",
        "hint": "Check interface counters and duplex settings.",
        "validate": {"R1": ("show interface gi1", r"Full.duplex|Auto.duplex")},
    },
    {
        "id": 3,
        "name": "Wrong Subnet Mask",
        "category": "Interface",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
            ],
        },
        "break_config": {"R2": ["interface gi1", "ip address 10.0.12.130 255.255.255.128"]},
        "description": "R1 (10.0.12.1) cannot ping R2. Both interfaces show up/up but pings fail. The IP was recently changed on R2.",
        "hint": "Check IP addresses and subnet masks on both sides. Are they on the same subnet?",
        "validate": {"R1": ("ping 10.0.12.2 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 4,
        "name": "Wrong IP on Interface",
        "category": "Interface",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
            ],
        },
        "break_config": {"R2": ["interface gi1", "ip address 10.0.99.2 255.255.255.0"]},
        "description": "R1 cannot reach R2. R2's interface should be 10.0.12.2/24. Find what's wrong.",
        "hint": "Check IP addressing on R2.",
        "validate": {"R1": ("ping 10.0.12.2 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 5,
        "name": "Speed Mismatch",
        "category": "Interface",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
            ],
        },
        "break_config": {"R1": ["interface gi1", "speed 100"]},
        "description": "The link between R1 and R2 is not coming up properly after a maintenance window. Investigate.",
        "hint": "Check speed and negotiation settings.",
        "validate": {"R1": ("show interface gi1", r"[Aa]uto.speed|1000Mb")},
    },
    {
        "id": 6,
        "name": "MTU Mismatch",
        "category": "Interface",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
            ],
        },
        "break_config": {"R1": ["interface gi1", "mtu 9000"]},
        "description": "Small pings to R2 work but large file transfers fail. OSPF neighbors won't form. Investigate.",
        "hint": "Check MTU settings on both sides. Try pinging with different sizes.",
        "validate": {"R1": ("show interface gi1 | include MTU", r"MTU 1500")},
    },
    {
        "id": 7,
        "name": "Interface Description Wrong Port",
        "category": "Interface",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi2", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi2", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
            ],
        },
        "break_config": {
            "R1": [
                "interface gi2", "shutdown",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
            ]
        },
        "description": "R1 is cabled to R2 via Gi2 but IP config was applied to Gi1 by a junior admin. Fix it.",
        "hint": "Check which interface has the cable and which has the IP.",
        "validate": {"R1": ("ping 10.0.12.2 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 8,
        "name": "IP Unnumbered Misconfigured",
        "category": "Interface",
        "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                "interface gi1", "ip unnumbered loopback0", "no shutdown",
                "ip route 2.2.2.2 255.255.255.255 gi1",
            ],
            "R2": [
                "hostname R2",
                "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                "interface gi1", "ip unnumbered loopback0", "no shutdown",
                "ip route 1.1.1.1 255.255.255.255 gi1",
            ],
        },
        "break_config": {"R1": ["no interface loopback0"]},
        "description": "R1 uses ip unnumbered on Gi1 referencing Loopback0, but connectivity to R2 is broken. Investigate.",
        "hint": "What happens to ip unnumbered when the referenced interface is missing?",
        "validate": {"R1": ("ping 2.2.2.2 source 1.1.1.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 9,
        "name": "Bandwidth Statement Confusion",
        "category": "Interface",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
        },
        "break_config": {"R1": ["interface gi1", "bandwidth 64"]},
        "description": "OSPF is working but R1's route to R2 shows an unusually high cost. Investigate the OSPF cost calculation.",
        "hint": "The bandwidth command affects OSPF cost calculation.",
        "validate": {"R1": ("show interface gi1 | include BW", r"BW 1000000")},
    },
    {
        "id": 10,
        "name": "Secondary IP Missing",
        "category": "Interface",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "interface gi1", "ip address 172.16.0.1 255.255.255.0 secondary",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 172.16.0.2 255.255.255.0", "no shutdown",
            ],
        },
        "break_config": {"R1": ["interface gi1", "no ip address 172.16.0.1 255.255.255.0 secondary"]},
        "description": "R2 (172.16.0.2) cannot reach R1. Both are on the same link. R1 has other connectivity working fine.",
        "hint": "R1's interface might need multiple IP addresses.",
        "validate": {"R2": ("ping 172.16.0.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },

    # ========== CATEGORY 2: STATIC ROUTING (11-20) ==========
    {
        "id": 11,
        "name": "Missing Default Route",
        "category": "Routing - Static",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                "ip route 0.0.0.0 0.0.0.0 10.0.12.2",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                "ip route 1.1.1.1 255.255.255.255 10.0.12.1",
            ],
        },
        "break_config": {"R2": ["no ip route 1.1.1.1 255.255.255.255 10.0.12.1"]},
        "description": "R1 can ping R2's Gi1 (10.0.12.2) but cannot reach R2's loopback (2.2.2.2). R2 cannot reach R1's loopback (1.1.1.1). Fix routing.",
        "hint": "Check the routing tables on both routers.",
        "validate": {"R1": ("ping 2.2.2.2 source 1.1.1.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 12,
        "name": "Wrong Next-Hop",
        "category": "Routing - Static",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "ip route 10.0.20.0 255.255.255.0 10.0.12.2",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 10.0.20.1 255.255.255.0",
            ],
        },
        "break_config": {"R1": ["no ip route 10.0.20.0 255.255.255.0 10.0.12.2", "ip route 10.0.20.0 255.255.255.0 10.0.12.99"]},
        "description": "R1 should be able to reach 10.0.20.0/24 via R2 but traffic is blackholed. Investigate.",
        "hint": "Check the static route next-hop on R1.",
        "validate": {"R1": ("ping 10.0.20.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 13,
        "name": "Asymmetric Routing",
        "category": "Routing - Static",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R1", "gi2", "R3", "gi1"), ("R2", "gi2", "R3", "gi2")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "interface gi2", "ip address 10.0.13.1 255.255.255.0", "no shutdown",
                "ip route 10.0.23.0 255.255.255.0 10.0.12.2",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                "ip route 10.0.13.0 255.255.255.0 10.0.12.1",
            ],
            "R3": [
                "hostname R3",
                "interface gi1", "ip address 10.0.13.3 255.255.255.0", "no shutdown",
                "interface gi2", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                "ip route 10.0.12.0 255.255.255.0 10.0.13.1",
            ],
        },
        "break_config": {"R2": ["no ip route 10.0.13.0 255.255.255.0 10.0.12.1", "ip route 10.0.13.0 255.255.255.0 10.0.23.3"]},
        "description": "Traffic from R1 to R3 goes through R2 but return traffic takes a different path. Traceroute shows asymmetric routing. Fix R2's routing so traffic is symmetric.",
        "hint": "Check R2's routing table for 10.0.13.0/24.",
        "validate": {"R2": ("show ip route 10.0.13.0", r"10.0.12.1")},
    },
    {
        "id": 14,
        "name": "Floating Static Not Floating",
        "category": "Routing - Static",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R1", "gi2", "R2", "gi2")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "interface gi2", "ip address 10.0.22.1 255.255.255.0", "no shutdown",
                "ip route 10.0.99.0 255.255.255.0 10.0.12.2",
                "ip route 10.0.99.0 255.255.255.0 10.0.22.2 200",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface gi2", "ip address 10.0.22.2 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 10.0.99.1 255.255.255.0",
                "ip route 10.0.0.0 255.255.0.0 10.0.12.1",
            ],
        },
        "break_config": {
            "R1": [
                "no ip route 10.0.99.0 255.255.255.0 10.0.12.2",
                "no ip route 10.0.99.0 255.255.255.0 10.0.22.2 200",
                "ip route 10.0.99.0 255.255.255.0 10.0.12.2",
                "ip route 10.0.99.0 255.255.255.0 10.0.22.2",
            ]
        },
        "description": "R1 has a primary and backup route to 10.0.99.0/24 via two links to R2. The backup should only be used if the primary link fails, but traffic is load-balancing across both. Fix it.",
        "hint": "Check administrative distances on the static routes.",
        "validate": {"R1": ("show ip route static | include 10.0.99.0", r"10.0.12.2")},
    },
    {
        "id": 15,
        "name": "Recursive Route Loop",
        "category": "Routing - Static",
        "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "ip route 192.168.1.0 255.255.255.0 10.0.12.2",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 192.168.1.1 255.255.255.0",
            ],
        },
        "break_config": {
            "R1": [
                "no ip route 192.168.1.0 255.255.255.0 10.0.12.2",
                "ip route 192.168.1.0 255.255.255.0 172.16.0.1",
                "ip route 172.16.0.0 255.255.255.0 192.168.1.1",
            ]
        },
        "description": "R1 cannot reach 192.168.1.0/24 on R2. The routes were recently changed. Investigate the routing table for loops.",
        "hint": "Check for recursive static route dependencies.",
        "validate": {"R1": ("ping 192.168.1.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 16,
        "name": "Null Route Blocking Traffic",
        "category": "Routing - Static",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "ip route 10.0.20.0 255.255.255.0 10.0.12.2",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 10.0.20.1 255.255.255.0",
            ],
        },
        "break_config": {"R1": ["ip route 10.0.20.0 255.255.0.0 null0"]},
        "description": "R1 cannot reach 10.0.20.0/24 on R2 even though a valid static route exists. Something is overriding it.",
        "hint": "Check for more specific or less specific routes that might interfere. Remember longest match wins.",
        "validate": {"R1": ("ping 10.0.20.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 17,
        "name": "Missing Return Route",
        "category": "Routing - Static",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                "ip route 2.2.2.2 255.255.255.255 10.0.12.2",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                "ip route 1.1.1.1 255.255.255.255 10.0.12.1",
            ],
        },
        "break_config": {"R2": ["no ip route 1.1.1.1 255.255.255.255 10.0.12.1"]},
        "description": "R1 pings 2.2.2.2 from source 1.1.1.1 but gets no reply. However, pinging 10.0.12.2 works fine. Fix it.",
        "hint": "If ping works to directly connected but not to loopbacks, think about return path.",
        "validate": {"R1": ("ping 2.2.2.2 source 1.1.1.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 18,
        "name": "Wrong Exit Interface",
        "category": "Routing - Static",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "interface gi2", "ip address 10.0.99.1 255.255.255.0", "no shutdown",
                "ip route 10.0.20.0 255.255.255.0 10.0.12.2",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 10.0.20.1 255.255.255.0",
                "ip route 10.0.0.0 255.0.0.0 10.0.12.1",
            ],
        },
        "break_config": {"R1": ["no ip route 10.0.20.0 255.255.255.0 10.0.12.2", "ip route 10.0.20.0 255.255.255.0 gi2"]},
        "description": "R1 should route 10.0.20.0/24 traffic to R2 via Gi1, but traffic is going out the wrong interface.",
        "hint": "Check which interface the static route points to.",
        "validate": {"R1": ("show ip route 10.0.20.0", r"10.0.12.2")},
    },
    {
        "id": 19,
        "name": "AD Override by Another Protocol",
        "category": "Routing - Static",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "ip route 10.0.20.0 255.255.255.0 10.0.12.2",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 10.0.20.1 255.255.255.0",
            ],
        },
        "break_config": {
            "R1": [
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
            "R2": [
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
                "network 10.0.20.0 0.0.0.255 area 0",
            ],
        },
        "description": "A static route to 10.0.20.0/24 exists on R1 but it's not being used. OSPF was recently enabled. Understand why and ensure the static route takes precedence.",
        "hint": "Compare administrative distances. Static = 1, OSPF = 110. But is the OSPF route being installed?",
        "validate": {"R1": ("show ip route 10.0.20.0", r"[Ss]tatic|10.0.12.2")},
    },
    {
        "id": 20,
        "name": "Summary Route Too Broad",
        "category": "Routing - Static",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 10.1.1.1 255.255.255.0",
                "ip route 0.0.0.0 0.0.0.0 10.0.12.2",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                "ip route 10.1.0.0 255.255.0.0 10.0.12.1",
                "ip route 10.2.0.0 255.255.0.0 10.0.23.3",
            ],
            "R3": [
                "hostname R3",
                "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 10.2.1.1 255.255.255.0",
                "ip route 0.0.0.0 0.0.0.0 10.0.23.2",
            ],
        },
        "break_config": {
            "R2": [
                "no ip route 10.1.0.0 255.255.0.0 10.0.12.1",
                "no ip route 10.2.0.0 255.255.0.0 10.0.23.3",
                "ip route 10.0.0.0 255.0.0.0 10.0.12.1",
            ]
        },
        "description": "R3 (10.2.1.1) cannot be reached from R1 (10.1.1.1). R2 is the transit router. All interfaces are up.",
        "hint": "Check R2's routing table. Is the summary route too broad?",
        "validate": {"R1": ("ping 10.2.1.1 source 10.1.1.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },

    # ========== CATEGORY 3: OSPF (21-30) ==========
    {
        "id": 21,
        "name": "OSPF Area Mismatch",
        "category": "OSPF",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
        },
        "break_config": {"R2": ["router ospf 1", "no network 10.0.12.0 0.0.0.255 area 0", "network 10.0.12.0 0.0.0.255 area 1"]},
        "description": "OSPF adjacency won't form between R1 and R2. Both have OSPF enabled on the correct interfaces.",
        "hint": "Check OSPF area configuration on both sides.",
        "validate": {"R1": ("show ip ospf neighbor", r"FULL")},
    },
    {
        "id": 22,
        "name": "OSPF Hello Timer Mismatch",
        "category": "OSPF",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
        },
        "break_config": {"R1": ["interface gi1", "ip ospf hello-interval 5"]},
        "description": "OSPF neighbors won't form between R1 and R2. Configuration looks correct. Investigate.",
        "hint": "OSPF requires matching hello and dead timers.",
        "validate": {"R1": ("show ip ospf neighbor", r"FULL")},
    },
    {
        "id": 23,
        "name": "OSPF Authentication Mismatch",
        "category": "OSPF",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "ip ospf authentication message-digest",
                "ip ospf message-digest-key 1 md5 cisco123",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "ip ospf authentication message-digest",
                "ip ospf message-digest-key 1 md5 cisco123",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
        },
        "break_config": {"R2": ["interface gi1", "ip ospf message-digest-key 1 md5 wrongpass"]},
        "description": "OSPF adjacency dropped after a password change on R2. OSPF log shows authentication failures.",
        "hint": "Check OSPF authentication keys on both sides.",
        "validate": {"R1": ("show ip ospf neighbor", r"FULL")},
    },
    {
        "id": 24,
        "name": "OSPF Network Type Mismatch",
        "category": "OSPF",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
        },
        "break_config": {"R1": ["interface gi1", "ip ospf network point-to-point"]},
        "description": "OSPF neighbors form but routes are not being exchanged properly. R1 was recently changed to point-to-point but R2 is still broadcast.",
        "hint": "OSPF network type must match on both sides for proper operation.",
        "validate": {"R1": ("show ip ospf interface gi1 | include Network", r"BROADCAST|POINT")},
    },
    {
        "id": 25,
        "name": "OSPF Passive Interface",
        "category": "OSPF",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
        },
        "break_config": {"R1": ["router ospf 1", "passive-interface gi1"]},
        "description": "OSPF adjacency won't form. Both routers have OSPF configured with correct areas and IPs. Debug shows no hellos from R1.",
        "hint": "Check if the interface is set to passive.",
        "validate": {"R1": ("show ip ospf neighbor", r"FULL")},
    },
    {
        "id": 26,
        "name": "OSPF Missing Network Statement",
        "category": "OSPF",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0", "network 1.1.1.1 0.0.0.0 area 0",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0", "network 2.2.2.2 0.0.0.0 area 0",
            ],
        },
        "break_config": {"R2": ["router ospf 1", "no network 2.2.2.2 0.0.0.0 area 0"]},
        "description": "R1 can see R2 as an OSPF neighbor but R2's loopback (2.2.2.2) doesn't appear in R1's routing table.",
        "hint": "Check OSPF network statements on R2.",
        "validate": {"R1": ("show ip route ospf", r"2.2.2.2")},
    },
    {
        "id": 27,
        "name": "OSPF Subnet Mask Mismatch",
        "category": "OSPF",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
        },
        "break_config": {"R2": ["interface gi1", "ip address 10.0.12.2 255.255.255.240"]},
        "description": "OSPF neighbors won't reach FULL state. Both routers have OSPF in area 0 but the adjacency is stuck.",
        "hint": "OSPF requires matching subnet masks on the shared link.",
        "validate": {"R1": ("show ip ospf neighbor", r"FULL")},
    },
    {
        "id": 28,
        "name": "OSPF Duplicate Router ID",
        "category": "OSPF",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "router ospf 1", "router-id 1.1.1.1", "network 10.0.12.0 0.0.0.255 area 0",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "router ospf 1", "router-id 2.2.2.2", "network 10.0.12.0 0.0.0.255 area 0",
            ],
        },
        "break_config": {"R2": ["router ospf 1", "router-id 1.1.1.1"]},
        "description": "OSPF is behaving erratically. Logs show duplicate router-id warnings. Fix the issue.",
        "hint": "Each OSPF router needs a unique router-id.",
        "validate": {"R2": ("show ip ospf | include Router ID", r"2.2.2.2")},
    },
    {
        "id": 29,
        "name": "OSPF Distribute List Blocking",
        "category": "OSPF",
        "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0",
            ],
        },
        "break_config": {
            "R2": [
                "access-list 10 deny 1.1.1.1 0.0.0.0", "access-list 10 permit any",
                "router ospf 1", "distribute-list 10 in",
            ]
        },
        "description": "R2 can see R1 as an OSPF neighbor and pings 10.0.12.1 fine, but 1.1.1.1 (R1's loopback) is not in R2's routing table.",
        "hint": "Check for any filtering applied to OSPF routes.",
        "validate": {"R2": ("show ip route ospf", r"1.1.1.1")},
    },
    {
        "id": 30,
        "name": "OSPF Virtual Link Needed",
        "category": "OSPF",
        "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": [
                "hostname R1",
                "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                "router ospf 1", "router-id 1.1.1.1",
                "network 10.0.12.0 0.0.0.255 area 0",
                "network 1.1.1.1 0.0.0.0 area 0",
            ],
            "R2": [
                "hostname R2",
                "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                "router ospf 1", "router-id 2.2.2.2",
                "network 10.0.12.0 0.0.0.255 area 0",
                "network 10.0.23.0 0.0.0.255 area 1",
                "network 2.2.2.2 0.0.0.0 area 0",
            ],
            "R3": [
                "hostname R3",
                "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                "router ospf 1", "router-id 3.3.3.3",
                "network 10.0.23.0 0.0.0.255 area 1",
                "network 3.3.3.3 0.0.0.0 area 1",
            ],
        },
        "break_config": {
            "R2": [
                "router ospf 1",
                "no network 10.0.12.0 0.0.0.255 area 0",
                "network 10.0.12.0 0.0.0.255 area 1",
            ]
        },
        "description": "R3 in area 1 cannot reach R1 in area 0. R2 connects both areas. After a config change, area 1 lost connectivity to area 0. R3's OSPF routes to area 0 disappeared.",
        "hint": "All OSPF areas must connect to area 0 (backbone). If not directly, a virtual-link through a transit area is needed.",
        "validate": {"R3": ("show ip route ospf", r"1.1.1.1")},
    },

    # ========== CATEGORY 4: EIGRP (31-40) ==========
    {
        "id": 31,
        "name": "EIGRP AS Mismatch",
        "category": "EIGRP",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 10.0.12.0 0.0.0.255"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 10.0.12.0 0.0.0.255"],
        },
        "break_config": {"R2": ["no router eigrp 100", "router eigrp 200", "network 10.0.12.0 0.0.0.255"]},
        "description": "EIGRP adjacency won't form between R1 and R2. Both have EIGRP enabled.",
        "hint": "EIGRP AS numbers must match.",
        "validate": {"R1": ("show ip eigrp neighbors", r"10.0.12.2")},
    },
    {
        "id": 32,
        "name": "EIGRP K-Value Mismatch",
        "category": "EIGRP",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 10.0.12.0 0.0.0.255"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 10.0.12.0 0.0.0.255"],
        },
        "break_config": {"R2": ["router eigrp 100", "metric weights 0 1 1 1 0 0"]},
        "description": "EIGRP neighbors keep forming and dropping. Logs show K-value mismatch.",
        "hint": "EIGRP metric weights (K-values) must match for neighbors to form.",
        "validate": {"R1": ("show ip eigrp neighbors", r"10.0.12.2")},
    },
    {
        "id": 33,
        "name": "EIGRP Passive Interface",
        "category": "EIGRP",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 10.0.12.0 0.0.0.255"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 10.0.12.0 0.0.0.255"],
        },
        "break_config": {"R1": ["router eigrp 100", "passive-interface default"]},
        "description": "EIGRP adjacency won't form. R1 was recently hardened with passive-interface default but forgot to exclude the peering link.",
        "hint": "Check passive interface configuration.",
        "validate": {"R1": ("show ip eigrp neighbors", r"10.0.12.2")},
    },
    {
        "id": 34,
        "name": "EIGRP Stuck in Active",
        "category": "EIGRP",
        "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "router eigrp 100", "network 0.0.0.0"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 0.0.0.0"],
            "R3": ["hostname R3", "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "router eigrp 100", "network 0.0.0.0"],
        },
        "break_config": {"R2": ["interface gi2", "ip summary-address eigrp 100 0.0.0.0 0.0.0.0"]},
        "description": "R3's loopback is unreachable from R1 after a change on R2. EIGRP shows the route as active (SIA). Investigate R2.",
        "hint": "Check for auto-summarization or manual summary routes that might be too broad.",
        "validate": {"R1": ("ping 3.3.3.3 source 1.1.1.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 35,
        "name": "EIGRP Authentication Failure",
        "category": "EIGRP",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "ip authentication mode eigrp 100 md5",
                    "ip authentication key-chain eigrp 100 EIGRP_KEY",
                    "key chain EIGRP_KEY", "key 1", "key-string cisco123",
                    "router eigrp 100", "network 10.0.12.0 0.0.0.255"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "ip authentication mode eigrp 100 md5",
                    "ip authentication key-chain eigrp 100 EIGRP_KEY",
                    "key chain EIGRP_KEY", "key 1", "key-string cisco123",
                    "router eigrp 100", "network 10.0.12.0 0.0.0.255"],
        },
        "break_config": {"R2": ["key chain EIGRP_KEY", "key 1", "key-string wrongkey"]},
        "description": "EIGRP neighbors dropped after a key rotation on R2. Fix the authentication.",
        "hint": "Check key-chain configuration and ensure key-strings match.",
        "validate": {"R1": ("show ip eigrp neighbors", r"10.0.12.2")},
    },
    {
        "id": 36,
        "name": "EIGRP Wrong Network Statement",
        "category": "EIGRP",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 10.0.12.0 0.0.0.255"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 10.0.12.0 0.0.0.255"],
        },
        "break_config": {"R2": ["router eigrp 100", "no network 10.0.12.0 0.0.0.255", "network 10.0.99.0 0.0.0.255"]},
        "description": "EIGRP adjacency won't form. R2 has EIGRP enabled but the network statement was recently changed.",
        "hint": "Check the EIGRP network statements match the interface subnets.",
        "validate": {"R1": ("show ip eigrp neighbors", r"10.0.12.2")},
    },
    {
        "id": 37,
        "name": "EIGRP Unequal Cost Load Balancing",
        "category": "EIGRP",
        "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R1", "gi2", "R3", "gi1"), ("R2", "gi2", "R3", "gi2")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.13.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "router eigrp 100", "network 0.0.0.0", "variance 2"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 0.0.0.0"],
            "R3": ["hostname R3", "interface gi1", "ip address 10.0.13.3 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "router eigrp 100", "network 0.0.0.0"],
        },
        "break_config": {"R1": ["router eigrp 100", "no variance 2"]},
        "description": "R1 should use both paths to reach R3's loopback (via R2 and direct) but only one path appears. Unequal cost load balancing was configured but stopped working.",
        "hint": "Check the EIGRP variance multiplier.",
        "validate": {"R1": ("show ip eigrp topology 3.3.3.3/32", r"via.*via")},
    },
    {
        "id": 38,
        "name": "EIGRP Route Filtering",
        "category": "EIGRP",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface loopback1", "ip address 10.1.1.1 255.255.255.0",
                    "router eigrp 100", "network 0.0.0.0"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 0.0.0.0"],
        },
        "break_config": {
            "R2": ["access-list 10 deny 1.1.1.1 0.0.0.0", "access-list 10 permit any",
                    "router eigrp 100", "distribute-list 10 in"]
        },
        "description": "R2 can reach R1's 10.1.1.0/24 loopback but not the 1.1.1.1/32 loopback. Both are advertised in EIGRP.",
        "hint": "Check for distribute-lists or route-maps filtering EIGRP routes.",
        "validate": {"R2": ("show ip route eigrp", r"1.1.1.1")},
    },
    {
        "id": 39,
        "name": "EIGRP Split Horizon",
        "category": "EIGRP",
        "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R1", "gi1", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.123.1 255.255.255.0", "no shutdown",
                    "no ip split-horizon eigrp 100",
                    "router eigrp 100", "network 0.0.0.0"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.123.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                    "router eigrp 100", "network 0.0.0.0"],
            "R3": ["hostname R3", "interface gi1", "ip address 10.0.123.3 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 0.0.0.0"],
        },
        "break_config": {"R1": ["interface gi1", "ip split-horizon eigrp 100"]},
        "description": "Hub-and-spoke EIGRP over shared segment. R3 cannot reach R2's loopback (2.2.2.2) even though R1 knows the route. R1 is the hub.",
        "hint": "On shared multi-access segments, split-horizon prevents advertising routes back out the same interface.",
        "validate": {"R3": ("show ip route eigrp", r"2.2.2.2")},
    },
    {
        "id": 40,
        "name": "EIGRP Auto-Summary Creating Blackhole",
        "category": "EIGRP",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 172.16.1.1 255.255.255.0",
                    "router eigrp 100", "no auto-summary", "network 0.0.0.0"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 172.16.2.1 255.255.255.0",
                    "router eigrp 100", "no auto-summary", "network 0.0.0.0"],
        },
        "break_config": {"R1": ["router eigrp 100", "auto-summary"]},
        "description": "R2 can no longer reach R1's loopback 172.16.1.0/24. R1 is summarizing routes unexpectedly.",
        "hint": "Check auto-summary behavior in EIGRP. Summary routes create null0 entries.",
        "validate": {"R2": ("ping 172.16.1.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },

    # ========== CATEGORY 5: BGP (41-50) ==========
    {
        "id": 41,
        "name": "BGP Wrong Neighbor IP",
        "category": "BGP",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router bgp 65001", "neighbor 10.0.12.2 remote-as 65002"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router bgp 65002", "neighbor 10.0.12.1 remote-as 65001"],
        },
        "break_config": {"R2": ["router bgp 65002", "no neighbor 10.0.12.1 remote-as 65001", "neighbor 10.0.12.99 remote-as 65001"]},
        "description": "eBGP peering won't establish between R1 (AS65001) and R2 (AS65002). Fix it.",
        "hint": "Check neighbor IP addresses on both sides.",
        "validate": {"R1": ("show bgp summary", r"65002.*[0-9]")},
    },
    {
        "id": 42,
        "name": "BGP Wrong Remote AS",
        "category": "BGP",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router bgp 65001", "neighbor 10.0.12.2 remote-as 65002"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router bgp 65002", "neighbor 10.0.12.1 remote-as 65001"],
        },
        "break_config": {"R1": ["router bgp 65001", "no neighbor 10.0.12.2 remote-as 65002", "neighbor 10.0.12.2 remote-as 65099"]},
        "description": "BGP peering stuck in Active/Idle state. The AS numbers were recently reorganized.",
        "hint": "Check remote-as numbers match the actual AS of each neighbor.",
        "validate": {"R1": ("show bgp summary", r"65002.*[0-9]")},
    },
    {
        "id": 43,
        "name": "BGP Missing Network Statement",
        "category": "BGP",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "router bgp 65001", "neighbor 10.0.12.2 remote-as 65002", "network 1.1.1.1 mask 255.255.255.255"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router bgp 65002", "neighbor 10.0.12.1 remote-as 65001"],
        },
        "break_config": {"R1": ["router bgp 65001", "no network 1.1.1.1 mask 255.255.255.255"]},
        "description": "BGP peering is up but R2 receives no prefixes from R1. R1's loopback (1.1.1.1) should be advertised.",
        "hint": "BGP requires explicit network statements or redistribution to advertise routes.",
        "validate": {"R2": ("show bgp", r"1.1.1.1")},
    },
    {
        "id": 44,
        "name": "iBGP Missing Next-Hop-Self",
        "category": "BGP",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router bgp 65001", "neighbor 10.0.12.2 remote-as 65001", "neighbor 10.0.12.2 next-hop-self",
                    "neighbor 10.0.12.2 route-reflector-client"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router bgp 65001", "neighbor 10.0.12.1 remote-as 65001",
                    "neighbor 10.0.23.3 remote-as 65002"],
            "R3": ["hostname R3", "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "router bgp 65002", "neighbor 10.0.23.2 remote-as 65001", "network 3.3.3.3 mask 255.255.255.255"],
        },
        "break_config": {"R2": ["router bgp 65001", "no neighbor 10.0.12.1 next-hop-self"]},
        "description": "R1 sees R3's prefix (3.3.3.3/32) in BGP but it shows as inaccessible with next-hop 10.0.23.3 which R1 can't reach directly.",
        "hint": "In iBGP, the next-hop is not changed by default. The next-hop-self command fixes this.",
        "validate": {"R1": ("show bgp 3.3.3.3", r"[Nn]ext [Hh]op.*10.0.12.2")},
    },
    {
        "id": 45,
        "name": "BGP Update-Source Missing",
        "category": "BGP",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0",
                    "router bgp 65001", "neighbor 2.2.2.2 remote-as 65001",
                    "neighbor 2.2.2.2 update-source loopback0"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0",
                    "router bgp 65001", "neighbor 1.1.1.1 remote-as 65001",
                    "neighbor 1.1.1.1 update-source loopback0"],
        },
        "break_config": {"R2": ["router bgp 65001", "no neighbor 1.1.1.1 update-source loopback0"]},
        "description": "iBGP peering between loopbacks won't establish. OSPF is working and loopbacks are reachable.",
        "hint": "BGP uses the outgoing interface IP as source by default. For loopback peering, update-source is needed.",
        "validate": {"R1": ("show bgp summary", r"2.2.2.2.*65001")},
    },
    {
        "id": 46,
        "name": "BGP eBGP Multihop",
        "category": "BGP",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "ip route 2.2.2.2 255.255.255.255 10.0.12.2",
                    "router bgp 65001", "neighbor 2.2.2.2 remote-as 65002",
                    "neighbor 2.2.2.2 update-source loopback0", "neighbor 2.2.2.2 ebgp-multihop 2"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                    "ip route 1.1.1.1 255.255.255.255 10.0.12.1",
                    "router bgp 65002", "neighbor 1.1.1.1 remote-as 65001",
                    "neighbor 1.1.1.1 update-source loopback0", "neighbor 1.1.1.1 ebgp-multihop 2"],
        },
        "break_config": {"R2": ["router bgp 65002", "no neighbor 1.1.1.1 ebgp-multihop 2"]},
        "description": "eBGP peering between loopbacks (1.1.1.1 <-> 2.2.2.2) won't come up. Static routes for reachability exist.",
        "hint": "eBGP has a default TTL of 1. Loopback peering needs multihop.",
        "validate": {"R1": ("show bgp summary", r"2.2.2.2.*65002")},
    },
    {
        "id": 47,
        "name": "BGP Route Not in RIB",
        "category": "BGP",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0",
                    "router bgp 65001", "neighbor 10.0.12.2 remote-as 65002", "network 192.168.1.0"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router bgp 65002", "neighbor 10.0.12.1 remote-as 65001"],
        },
        "break_config": {"R1": ["interface loopback0", "ip address 192.168.1.1 255.255.255.128"]},
        "description": "R1 has 'network 192.168.1.0' in BGP but R2 doesn't receive it. The BGP session is up.",
        "hint": "BGP network statement requires an exact match in the routing table. Check if the subnet matches.",
        "validate": {"R2": ("show bgp", r"192.168.1.0")},
    },
    {
        "id": 48,
        "name": "BGP Prefix-List Blocking",
        "category": "BGP",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "router bgp 65001", "neighbor 10.0.12.2 remote-as 65002", "network 1.1.1.1 mask 255.255.255.255"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router bgp 65002", "neighbor 10.0.12.1 remote-as 65001"],
        },
        "break_config": {
            "R2": [
                "ip prefix-list DENY_ALL seq 5 deny 0.0.0.0/0 le 32",
                "router bgp 65002", "neighbor 10.0.12.1 prefix-list DENY_ALL in",
            ]
        },
        "description": "BGP session is established but R2 has no BGP routes from R1. Something is filtering inbound.",
        "hint": "Check for prefix-lists or route-maps applied to the BGP neighbor.",
        "validate": {"R2": ("show bgp", r"1.1.1.1")},
    },
    {
        "id": 49,
        "name": "BGP Route-Map Deny",
        "category": "BGP",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "router bgp 65001", "neighbor 10.0.12.2 remote-as 65002", "network 1.1.1.1 mask 255.255.255.255"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router bgp 65002", "neighbor 10.0.12.1 remote-as 65001"],
        },
        "break_config": {
            "R1": [
                "route-map BLOCK_ALL deny 10",
                "router bgp 65001", "neighbor 10.0.12.2 route-map BLOCK_ALL out",
            ]
        },
        "description": "BGP peering is up but R1 is not sending any prefixes to R2. R1 has routes to advertise.",
        "hint": "Check for outbound route-maps on R1's BGP neighbor config.",
        "validate": {"R2": ("show bgp", r"1.1.1.1")},
    },
    {
        "id": 50,
        "name": "BGP Community Blackhole",
        "category": "BGP",
        "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "router bgp 65001", "neighbor 10.0.12.2 remote-as 65002",
                    "network 1.1.1.1 mask 255.255.255.255"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router bgp 65002", "neighbor 10.0.12.1 remote-as 65001",
                    "neighbor 10.0.12.1 send-community"],
        },
        "break_config": {
            "R1": [
                "route-map TAG_BLACKHOLE permit 10", "set community no-export",
                "router bgp 65001", "neighbor 10.0.12.2 route-map TAG_BLACKHOLE out",
                "neighbor 10.0.12.2 send-community",
            ]
        },
        "description": "R2 receives R1's prefix (1.1.1.1/32) but it's marked with a community that prevents further advertisement. R2 can reach it but downstream routers can't.",
        "hint": "Check BGP community attributes. no-export prevents advertisement to external peers.",
        "validate": {"R2": ("show bgp 1.1.1.1/32 | include Community", r"^(?!.*no-export)")},
    },

    # ========== CATEGORY 6: ACL / SECURITY (51-60) ==========
    {
        "id": 51,
        "name": "ACL Blocking All Traffic",
        "category": "ACL",
        "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {"R1": ["access-list 100 deny ip any any", "interface gi1", "ip access-group 100 in"]},
        "description": "R1 cannot receive any traffic from R2. Pings from R2 to R1 fail. All was working before a security change.",
        "hint": "Check for access-lists applied to interfaces.",
        "validate": {"R2": ("ping 10.0.12.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 52,
        "name": "ACL Wrong Direction",
        "category": "ACL",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "ip route 0.0.0.0 0.0.0.0 10.0.12.2"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                    "ip route 1.1.1.1 255.255.255.255 10.0.12.1"],
        },
        "break_config": {
            "R1": [
                "access-list 100 permit icmp any any",
                "access-list 100 deny ip any any",
                "interface gi1", "ip access-group 100 out",
            ]
        },
        "description": "ACL was applied to allow only ICMP outbound on R1's Gi1, but all traffic including SSH is being blocked when it shouldn't be. The ACL direction seems wrong.",
        "hint": "Check the ACL direction (in vs out) and what traffic it actually affects.",
        "validate": {"R1": ("show ip interface gi1", r"Outgoing.*not set|Outgoing.*100")},
    },
    {
        "id": 53,
        "name": "ACL Implicit Deny Forgot Permit",
        "category": "ACL",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {
            "R1": [
                "access-list 100 deny icmp 10.0.12.0 0.0.0.255 any echo",
                "interface gi1", "ip access-group 100 in",
            ]
        },
        "description": "Security team added an ACL to block pings on R1. But now ALL traffic from R2 is blocked, not just ICMP. The ACL only has a deny for ICMP echo.",
        "hint": "Remember the implicit deny at the end of every ACL.",
        "validate": {"R2": ("ping 10.0.12.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 54,
        "name": "ACL Blocking OSPF",
        "category": "ACL",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0"],
        },
        "break_config": {
            "R1": [
                "access-list 100 permit tcp any any",
                "access-list 100 permit udp any any",
                "access-list 100 permit icmp any any",
                "interface gi1", "ip access-group 100 in",
            ]
        },
        "description": "OSPF adjacency dropped after an ACL was applied to R1. Pings between routers still work. The ACL allows TCP, UDP, and ICMP.",
        "hint": "OSPF uses protocol 89 — it's neither TCP nor UDP.",
        "validate": {"R1": ("show ip ospf neighbor", r"FULL")},
    },
    {
        "id": 55,
        "name": "VTY ACL Lockout",
        "category": "ACL",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "line vty 0 4", "transport input ssh telnet", "login local",
                    "username admin privilege 15 secret cisco"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {
            "R1": [
                "access-list 5 permit 10.0.99.0 0.0.0.255",
                "line vty 0 4", "access-class 5 in",
            ]
        },
        "description": "Nobody can SSH/telnet to R1 anymore after a VTY ACL change. Console access still works. R1 is pingable.",
        "hint": "Check the VTY access-class and what source IPs it permits.",
        "validate": {"R1": ("show run | section line vty", r"access-class.*in|no access-class")},
    },
    {
        "id": 56,
        "name": "Named ACL Misconfigured",
        "category": "ACL",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 2.2.2.2 255.255.255.255"],
        },
        "break_config": {
            "R1": [
                "ip access-list extended ALLOW_R2",
                "permit ip host 10.0.12.2 any",
                "deny ip any any",
                "interface gi1", "ip access-group ALLOW_R2 in",
            ]
        },
        "description": "R1 can receive traffic from R2's directly connected interface but not from R2's loopback (2.2.2.2). The ACL should allow all traffic from R2.",
        "hint": "Check the source IP in the ACL — does it cover all of R2's addresses?",
        "validate": {"R1": ("ping 10.0.12.1 source 2.2.2.2", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 57,
        "name": "ACL Log Keyword Performance",
        "category": "ACL",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {
            "R1": [
                "access-list 100 permit ip any any log",
                "interface gi1", "ip access-group 100 in",
            ]
        },
        "description": "R1's CPU spiked to 100% after an ACL was applied. Traffic is passing but the router is nearly unusable. The ACL only has permit statements.",
        "hint": "The 'log' keyword on high-traffic ACL entries causes massive CPU load.",
        "validate": {"R1": ("show access-list 100", r"permit ip any any$")},
    },
    {
        "id": 58,
        "name": "Standard ACL on Wrong Interface",
        "category": "ACL",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "ip route 10.0.23.0 255.255.255.0 10.0.12.2"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown"],
            "R3": ["hostname R3", "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "ip route 10.0.12.0 255.255.255.0 10.0.23.2"],
        },
        "break_config": {
            "R2": [
                "access-list 1 deny 10.0.12.0 0.0.0.255",
                "access-list 1 permit any",
                "interface gi1", "ip access-group 1 in",
            ]
        },
        "description": "R1 cannot reach R3 through R2. R2 has an ACL that should block a specific subnet but it's applied to the wrong interface, blocking legitimate traffic.",
        "hint": "Standard ACLs should be placed close to the destination.",
        "validate": {"R1": ("ping 10.0.23.3 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 59,
        "name": "ACL Established Keyword",
        "category": "ACL",
        "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {
            "R1": [
                "access-list 100 permit tcp any any established",
                "interface gi1", "ip access-group 100 in",
            ]
        },
        "description": "R2 cannot initiate TCP connections to R1 (SSH, HTTP). But if R1 initiates a connection to R2, the return traffic works. Pings also fail.",
        "hint": "The 'established' keyword only allows TCP packets with ACK/RST flags set — it blocks SYN (new connections) and non-TCP.",
        "validate": {"R2": ("ping 10.0.12.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 60,
        "name": "Time-Based ACL Expired",
        "category": "ACL",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {
            "R1": [
                "time-range BUSINESS_HOURS", "periodic weekdays 8:00 to 17:00",
                "ip access-list extended TIMED_ACL",
                "permit ip any any time-range BUSINESS_HOURS",
                "interface gi1", "ip access-group TIMED_ACL in",
            ]
        },
        "description": "Traffic to R1 works during business hours but stops after 5 PM. There's a time-based ACL. Make it work 24/7.",
        "hint": "Check for time-range objects applied to ACL entries.",
        "validate": {"R1": ("show ip access-list TIMED_ACL", r"permit ip any any$")},
    },

    # ========== CATEGORY 7: NAT (61-70) ==========
    {
        "id": 61,
        "name": "NAT Inside/Outside Reversed",
        "category": "NAT",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "ip nat outside", "no shutdown",
                    "interface gi2", "ip address 192.168.1.1 255.255.255.0", "ip nat inside", "no shutdown",
                    "access-list 1 permit 192.168.1.0 0.0.0.255",
                    "ip nat inside source list 1 interface gi1 overload"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {"R1": ["interface gi1", "no ip nat outside", "ip nat inside",
                                  "interface gi2", "no ip nat inside", "ip nat outside"]},
        "description": "NAT stopped working after a junior admin changed interface configs. Internal hosts (192.168.1.0/24) can't reach the internet through R1.",
        "hint": "Check which interfaces are marked as NAT inside vs outside.",
        "validate": {"R1": ("show ip nat statistics", r"inside source")},
    },
    {
        "id": 62,
        "name": "NAT ACL Not Matching",
        "category": "NAT",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "ip nat outside", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0", "ip nat inside",
                    "access-list 1 permit 192.168.1.0 0.0.0.255",
                    "ip nat inside source list 1 interface gi1 overload"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {"R1": ["no access-list 1", "access-list 1 permit 192.168.99.0 0.0.0.255"]},
        "description": "PAT (overload NAT) is configured but traffic from 192.168.1.0/24 is not being translated. NAT translations table is empty.",
        "hint": "Check if the NAT ACL matches the actual source addresses.",
        "validate": {"R1": ("show access-list 1", r"192.168.1.0")},
    },
    {
        "id": 63,
        "name": "Static NAT Wrong Translation",
        "category": "NAT",
        "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "ip nat outside", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.10 255.255.255.0", "ip nat inside",
                    "ip nat inside source static 192.168.1.10 10.0.12.10"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "ip route 10.0.12.10 255.255.255.255 10.0.12.1"],
        },
        "break_config": {"R1": ["no ip nat inside source static 192.168.1.10 10.0.12.10",
                                  "ip nat inside source static 192.168.1.10 10.0.12.99"]},
        "description": "R2 tries to reach 10.0.12.10 (static NAT for internal server 192.168.1.10) but gets no response. The static NAT was recently modified.",
        "hint": "Check the NAT translation and ensure the public IP matches what R2 is trying to reach.",
        "validate": {"R1": ("show ip nat translations", r"10.0.12.10.*192.168.1.10")},
    },
    {
        "id": 64,
        "name": "NAT Missing Route",
        "category": "NAT",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "ip nat outside", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0", "ip nat inside",
                    "ip nat pool NATPOOL 10.0.12.100 10.0.12.110 netmask 255.255.255.0",
                    "access-list 1 permit 192.168.1.0 0.0.0.255",
                    "ip nat inside source list 1 pool NATPOOL",
                    "ip route 192.168.1.0 255.255.255.0 null0"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "ip route 10.0.12.100 255.255.255.255 10.0.12.1"],
        },
        "break_config": {"R2": ["no ip route 10.0.12.100 255.255.255.255 10.0.12.1"]},
        "description": "R1 translates 192.168.1.0/24 to pool 10.0.12.100-110. Traffic from R1 reaches R2 but return traffic from R2 never comes back. NAT is working on R1.",
        "hint": "R2 needs to know how to reach the NAT pool addresses.",
        "validate": {"R2": ("show ip route 10.0.12.100", r"10.0.12.1")},
    },
    {
        "id": 65,
        "name": "NAT Pool Exhaustion",
        "category": "NAT",
        "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "ip nat outside", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0", "ip nat inside",
                    "ip nat pool NATPOOL 10.0.12.100 10.0.12.110 netmask 255.255.255.0",
                    "access-list 1 permit 192.168.1.0 0.0.0.255",
                    "ip nat inside source list 1 pool NATPOOL overload"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {"R1": [
            "no ip nat inside source list 1 pool NATPOOL overload",
            "no ip nat pool NATPOOL 10.0.12.100 10.0.12.110 netmask 255.255.255.0",
            "ip nat pool TINYPOOL 10.0.12.100 10.0.12.100 netmask 255.255.255.0",
            "ip nat inside source list 1 pool TINYPOOL",
        ]},
        "description": "Only the first internal host can access the internet. Subsequent connections fail. NAT translations show only one entry.",
        "hint": "Check if the NAT pool is too small and whether PAT (overload) is enabled.",
        "validate": {"R1": ("show run | include overload", r"overload")},
    },
    {
        "id": 66, "name": "NAT Order of Operations", "category": "NAT", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "ip nat outside", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0", "ip nat inside",
                    "access-list 1 permit 192.168.1.0 0.0.0.255",
                    "ip nat inside source list 1 interface gi1 overload",
                    "ip route 0.0.0.0 0.0.0.0 10.0.12.2"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {
            "R1": ["access-list 100 permit ip 192.168.1.0 0.0.0.255 any",
                    "interface gi1", "ip access-group 100 out"]
        },
        "description": "NAT is configured correctly but outbound ACL on the outside interface is blocking translated traffic. The ACL permits 192.168.1.0/24 but traffic is already translated when it hits the outbound ACL.",
        "hint": "NAT happens BEFORE outbound ACL evaluation. The source is already translated.",
        "validate": {"R1": ("show ip access-list 100", r"permit ip any any|permit ip 10")},
    },
    {
        "id": 67, "name": "NAT Hairpinning", "category": "NAT", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "ip nat outside", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0", "ip nat inside"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {},
        "description": "This is a design question: internal host 192.168.1.1 has a static NAT to 10.0.12.10. External host R2 can reach 10.0.12.10 fine. But another internal host trying to reach 10.0.12.10 fails. Configure NAT hairpinning.",
        "hint": "Internal hosts trying to reach the public NAT IP need the router to translate both source and destination (NAT hairpin/loopback).",
        "validate": {"R1": ("show ip nat translations", r"192.168.1")},
    },
    {
        "id": 68, "name": "NAT with VPN Conflict", "category": "NAT", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "ip nat outside", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0", "ip nat inside",
                    "access-list 1 permit 192.168.1.0 0.0.0.255",
                    "ip nat inside source list 1 interface gi1 overload"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.2.1 255.255.255.0",
                    "ip route 192.168.1.0 255.255.255.0 10.0.12.1"],
        },
        "break_config": {},
        "description": "R1 NATs 192.168.1.0/24 to its outside interface. But now you need site-to-site connectivity where R2's 192.168.2.0/24 should reach 192.168.1.0/24 WITHOUT NAT. Fix NAT to exclude VPN traffic.",
        "hint": "Use a route-map with the NAT statement to exclude traffic destined for the remote site.",
        "validate": {"R2": ("ping 192.168.1.1 source 192.168.2.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 69, "name": "NAT Port Forwarding Wrong Port", "category": "NAT", "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "ip nat outside", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.10 255.255.255.0", "ip nat inside",
                    "ip nat inside source static tcp 192.168.1.10 80 10.0.12.1 80"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {"R1": ["no ip nat inside source static tcp 192.168.1.10 80 10.0.12.1 80",
                                  "ip nat inside source static tcp 192.168.1.10 80 10.0.12.1 8080"]},
        "description": "External users hitting port 80 on 10.0.12.1 can't reach the internal web server (192.168.1.10:80). Port forwarding was recently changed.",
        "hint": "Check the NAT port translation mapping.",
        "validate": {"R1": ("show ip nat translations", r"80.*80.*192.168.1.10")},
    },
    {
        "id": 70, "name": "NAT Overlapping Subnets", "category": "NAT", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0"],
        },
        "break_config": {},
        "description": "Both R1 and R2 have 192.168.1.0/24 internally (overlapping subnets). Configure NAT on both sides so they can communicate. R1's internal should appear as 172.16.1.0/24 and R2's as 172.16.2.0/24.",
        "hint": "Use 'ip nat outside source' for the remote side and 'ip nat inside source' for the local side.",
        "validate": {"R1": ("show ip nat translations", r"172.16")},
    },

    # ========== CATEGORY 8: VPN / GRE (71-80) ==========
    {
        "id": 71, "name": "GRE Tunnel Source Wrong", "category": "VPN/GRE", "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.1 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.2"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.2 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.1"],
        },
        "break_config": {"R1": ["interface tunnel0", "tunnel source loopback0"]},
        "description": "GRE tunnel between R1 and R2 is down. R2's tunnel destination is 10.0.12.1 but R1's tunnel source was changed.",
        "hint": "The tunnel source must match what the remote end expects as the destination.",
        "validate": {"R1": ("ping 172.16.0.2 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 72, "name": "GRE Recursive Routing", "category": "VPN/GRE", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.1 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.2",
                    "ip route 10.0.12.0 255.255.255.0 gi1"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.2 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.1"],
        },
        "break_config": {
            "R1": ["router ospf 1", "network 172.16.0.0 0.0.0.255 area 0", "network 10.0.12.0 0.0.0.255 area 0"],
            "R2": ["router ospf 1", "network 172.16.0.0 0.0.0.255 area 0", "network 10.0.12.0 0.0.0.255 area 0"],
        },
        "description": "GRE tunnel with OSPF over it keeps flapping. The tunnel goes up, OSPF learns a route to the tunnel destination via the tunnel itself, tunnel goes down, repeat.",
        "hint": "This is recursive routing. The tunnel destination must be reachable via the underlay, not the overlay.",
        "validate": {"R1": ("show ip route 10.0.12.0", r"directly connected|via.*gi1")},
    },
    {
        "id": 73, "name": "GRE Tunnel Key Mismatch", "category": "VPN/GRE", "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.1 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.2", "tunnel key 100"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.2 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.1", "tunnel key 100"],
        },
        "break_config": {"R2": ["interface tunnel0", "tunnel key 200"]},
        "description": "GRE tunnel interfaces show up/up but no traffic passes. Pings across the tunnel fail.",
        "hint": "Check tunnel keys on both sides.",
        "validate": {"R1": ("ping 172.16.0.2 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 74, "name": "GRE MTU/Fragmentation", "category": "VPN/GRE", "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.1 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.2",
                    "ip mtu 1400", "ip tcp adjust-mss 1360"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.2 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.1",
                    "ip mtu 1400", "ip tcp adjust-mss 1360"],
        },
        "break_config": {"R1": ["interface tunnel0", "ip mtu 1500", "no ip tcp adjust-mss"]},
        "description": "Small pings across the GRE tunnel work but large transfers stall. SSH works but SCP/large file transfers hang.",
        "hint": "GRE adds 24 bytes of overhead. Check MTU and MSS settings on the tunnel interface.",
        "validate": {"R1": ("show interface tunnel0 | include MTU", r"MTU 14[0-9][0-9]")},
    },
    {
        "id": 75, "name": "GRE Keepalive Failure", "category": "VPN/GRE", "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.1 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.2",
                    "keepalive 10 3"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.2 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.1"],
        },
        "break_config": {"R1": ["interface tunnel0", "keepalive 1 1"]},
        "description": "GRE tunnel on R1 keeps flapping. It comes up briefly then goes down. R2's side stays up.",
        "hint": "Check keepalive timers. If too aggressive, minor delays cause the tunnel to drop.",
        "validate": {"R1": ("show interface tunnel0", r"up.*up|Tunnel0 is up")},
    },
    {
        "id": 76, "name": "DMVPN NHRP Registration", "category": "VPN/GRE", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.1 255.255.255.0",
                    "tunnel source gi1", "tunnel mode gre multipoint",
                    "ip nhrp network-id 1", "ip nhrp map multicast dynamic"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.2 255.255.255.0",
                    "tunnel source gi1", "tunnel mode gre multipoint",
                    "ip nhrp network-id 1",
                    "ip nhrp nhs 172.16.0.1 nbma 10.0.12.1 multicast",
                    "ip nhrp map 172.16.0.1 10.0.12.1"],
        },
        "break_config": {"R2": ["interface tunnel0", "no ip nhrp nhs 172.16.0.1 nbma 10.0.12.1 multicast",
                                  "ip nhrp nhs 172.16.0.1 nbma 10.0.12.99 multicast"]},
        "description": "DMVPN spoke (R2) cannot register with hub (R1). NHRP registration fails.",
        "hint": "Check the NBMA address in the NHS statement matches the hub's actual transport address.",
        "validate": {"R1": ("show ip nhrp", r"172.16.0.2.*10.0.12.2")},
    },
    {
        "id": 77, "name": "IPsec Phase 1 Mismatch", "category": "VPN/GRE", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "crypto isakmp policy 10", "encryption aes 256", "hash sha256",
                    "authentication pre-share", "group 14",
                    "crypto isakmp key cisco123 address 10.0.12.2"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "crypto isakmp policy 10", "encryption aes 256", "hash sha256",
                    "authentication pre-share", "group 14",
                    "crypto isakmp key cisco123 address 10.0.12.1"],
        },
        "break_config": {"R2": ["crypto isakmp policy 10", "encryption aes 128"]},
        "description": "IPsec tunnel won't establish. Phase 1 (IKE) fails. Both sides use pre-shared keys.",
        "hint": "All IKE phase 1 parameters must match: encryption, hash, auth method, DH group.",
        "validate": {"R1": ("show crypto isakmp sa", r"QM_IDLE|MM_KEY_EXCH")},
    },
    {
        "id": 78, "name": "IPsec Pre-Shared Key Mismatch", "category": "VPN/GRE", "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "crypto isakmp policy 10", "encryption aes 256", "authentication pre-share",
                    "crypto isakmp key SecretKey123 address 10.0.12.2"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "crypto isakmp policy 10", "encryption aes 256", "authentication pre-share",
                    "crypto isakmp key SecretKey123 address 10.0.12.1"],
        },
        "break_config": {"R2": ["crypto isakmp key WrongKey999 address 10.0.12.1"]},
        "description": "VPN tunnel fails to establish after a key change on R2. IKE negotiation fails.",
        "hint": "Pre-shared keys must match on both sides.",
        "validate": {"R2": ("show run | include isakmp key", r"SecretKey123")},
    },
    {
        "id": 79, "name": "Crypto ACL Mismatch", "category": "VPN/GRE", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0",
                    "access-list 101 permit ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.2.1 255.255.255.0",
                    "access-list 101 permit ip 192.168.2.0 0.0.0.255 192.168.1.0 0.0.0.255"],
        },
        "break_config": {"R2": ["no access-list 101",
                                  "access-list 101 permit ip 192.168.2.0 0.0.0.255 192.168.99.0 0.0.0.255"]},
        "description": "IPsec tunnel establishes but no traffic is encrypted. Phase 2 SA won't form. The crypto ACLs define interesting traffic.",
        "hint": "Crypto ACLs must be mirror images of each other.",
        "validate": {"R2": ("show access-list 101", r"192.168.1.0")},
    },
    {
        "id": 80, "name": "GRE over IPsec Transport Issue", "category": "VPN/GRE", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.1 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.2",
                    "tunnel protection ipsec profile GRE_IPSEC"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.2 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.1",
                    "tunnel protection ipsec profile GRE_IPSEC"],
        },
        "break_config": {"R2": ["interface tunnel0", "no tunnel protection ipsec profile GRE_IPSEC"]},
        "description": "GRE tunnel works but traffic is NOT encrypted. R1 has IPsec protection on the tunnel but R2 doesn't. Fix R2.",
        "hint": "Both ends need the same IPsec profile applied to the tunnel interface.",
        "validate": {"R2": ("show run interface tunnel0", r"tunnel protection ipsec")},
    },

    # ========== CATEGORY 9: SERVICES / DHCP / NTP / LOGGING (81-90) ==========
    {
        "id": 81, "name": "DHCP Pool Wrong Network", "category": "Services", "difficulty": 1,
        "devices": [("R1", "csr")],
        "links": [],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 192.168.1.1 255.255.255.0", "no shutdown",
                    "ip dhcp pool LAN", "network 192.168.1.0 255.255.255.0",
                    "default-router 192.168.1.1", "dns-server 8.8.8.8"],
        },
        "break_config": {"R1": ["ip dhcp pool LAN", "no network 192.168.1.0 255.255.255.0",
                                  "network 192.168.99.0 255.255.255.0"]},
        "description": "DHCP clients are not getting IP addresses. The DHCP pool was recently modified.",
        "hint": "Check if the DHCP pool network matches the interface subnet.",
        "validate": {"R1": ("show run | section dhcp", r"192.168.1.0")},
    },
    {
        "id": 82, "name": "DHCP Excluded Range Too Broad", "category": "Services", "difficulty": 2,
        "devices": [("R1", "csr")],
        "links": [],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 192.168.1.1 255.255.255.0", "no shutdown",
                    "ip dhcp excluded-address 192.168.1.1 192.168.1.10",
                    "ip dhcp pool LAN", "network 192.168.1.0 255.255.255.0",
                    "default-router 192.168.1.1"],
        },
        "break_config": {"R1": ["ip dhcp excluded-address 192.168.1.1 192.168.1.254"]},
        "description": "DHCP pool shows 0 available addresses. No clients can get an IP but the pool is configured.",
        "hint": "Check the excluded address range.",
        "validate": {"R1": ("show ip dhcp pool", r"[1-9][0-9]* addresses")},
    },
    {
        "id": 83, "name": "DHCP Relay Missing", "category": "Services", "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 192.168.1.1 255.255.255.0", "no shutdown",
                    "ip helper-address 10.0.12.2"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "ip dhcp pool REMOTE", "network 192.168.1.0 255.255.255.0",
                    "default-router 192.168.1.1", "dns-server 8.8.8.8"],
        },
        "break_config": {"R1": ["interface gi2", "no ip helper-address 10.0.12.2"]},
        "description": "Remote subnet 192.168.1.0/24 behind R1 cannot get DHCP addresses from the server on R2. DHCP server is working for local clients.",
        "hint": "DHCP broadcasts don't cross routers without a relay/helper address.",
        "validate": {"R1": ("show run interface gi2", r"helper-address")},
    },
    {
        "id": 84, "name": "NTP Wrong Server", "category": "Services", "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "ntp server 10.0.12.2"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "ntp master 3"],
        },
        "break_config": {"R1": ["no ntp server 10.0.12.2", "ntp server 10.0.12.99"]},
        "description": "R1's clock is out of sync. NTP is configured but pointing to the wrong server.",
        "hint": "Check NTP server configuration and associations.",
        "validate": {"R1": ("show ntp associations", r"10.0.12.2")},
    },
    {
        "id": 85, "name": "NTP Authentication Failure", "category": "Services", "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "ntp authenticate", "ntp authentication-key 1 md5 ntpkey",
                    "ntp trusted-key 1", "ntp server 10.0.12.2 key 1"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "ntp authenticate", "ntp authentication-key 1 md5 ntpkey",
                    "ntp trusted-key 1", "ntp master 3"],
        },
        "break_config": {"R1": ["ntp authentication-key 1 md5 wrongkey"]},
        "description": "NTP sync failing after a key change. Authentication is required.",
        "hint": "NTP authentication keys must match on both sides.",
        "validate": {"R1": ("show ntp status", r"synchronized|Clock is synchronized")},
    },
    {
        "id": 86, "name": "Syslog Wrong Destination", "category": "Services", "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "logging host 10.0.12.2", "logging trap informational"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {"R1": ["no logging host 10.0.12.2", "logging host 10.0.12.99"]},
        "description": "Syslog server on R2 stopped receiving logs from R1. The logging config was changed.",
        "hint": "Check the logging host address.",
        "validate": {"R1": ("show logging | include Logging to", r"10.0.12.2")},
    },
    {
        "id": 87, "name": "SSH Not Enabled", "category": "Services", "difficulty": 2,
        "devices": [("R1", "csr")],
        "links": [],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "ip domain-name lab.local", "crypto key generate rsa modulus 2048",
                    "username admin privilege 15 secret cisco",
                    "line vty 0 4", "transport input ssh", "login local"],
        },
        "break_config": {"R1": ["line vty 0 4", "transport input none"]},
        "description": "SSH to R1 is refused. The VTY lines were recently modified.",
        "hint": "Check VTY transport input settings.",
        "validate": {"R1": ("show run | section line vty", r"transport input.*ssh")},
    },
    {
        "id": 88, "name": "SNMP Wrong Community", "category": "Services", "difficulty": 1,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "snmp-server community public RO"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown"],
        },
        "break_config": {"R1": ["no snmp-server community public RO", "snmp-server community pr1vate RO"]},
        "description": "SNMP monitoring stopped working for R1. The monitoring system uses community string 'public'.",
        "hint": "Check SNMP community strings.",
        "validate": {"R1": ("show snmp community", r"public")},
    },
    {
        "id": 89, "name": "DNS Lookup Disabled", "category": "Services", "difficulty": 1,
        "devices": [("R1", "csr")],
        "links": [],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "ip domain-lookup", "ip name-server 8.8.8.8"],
        },
        "break_config": {"R1": ["no ip domain-lookup"]},
        "description": "R1 cannot resolve hostnames. DNS was working before.",
        "hint": "Check if DNS lookup is enabled.",
        "validate": {"R1": ("show run | include domain-lookup", r"ip domain.lookup|^$")},
    },
    {
        "id": 90, "name": "Banners Missing", "category": "Services", "difficulty": 1,
        "devices": [("R1", "csr")],
        "links": [],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "banner motd ^Authorized access only. All activity is logged.^"],
        },
        "break_config": {"R1": ["no banner motd"]},
        "description": "Compliance audit found R1 is missing its login banner. Add it back.",
        "hint": "Use 'banner motd' command.",
        "validate": {"R1": ("show run | include banner", r"banner motd")},
    },

    # ========== CATEGORY 10: MULTI-PROTOCOL / COMPLEX (91-100) ==========
    {
        "id": 91, "name": "Redistribution Loop", "category": "Advanced", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1"), ("R3", "gi2", "R1", "gi2")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.31.1 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
                    "router eigrp 100", "network 10.0.31.0 0.0.0.255",
                    "redistribute ospf 1 metric 10000 100 255 1 1500"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0", "network 10.0.23.0 0.0.0.255 area 0"],
            "R3": ["hostname R3",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.31.3 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 10.0.23.0 0.0.0.255 area 0",
                    "redistribute eigrp 100 subnets",
                    "router eigrp 100", "network 10.0.31.0 0.0.0.255"],
        },
        "break_config": {
            "R1": ["router ospf 1", "redistribute eigrp 100 subnets"],
        },
        "description": "After adding mutual redistribution between OSPF and EIGRP, routing loops appeared. R1 redistributes in both directions without filtering.",
        "hint": "Use route tags or distribute-lists to prevent routes from being redistributed back into their source protocol.",
        "validate": {"R1": ("show ip route", r"10.0.23.0")},
    },
    {
        "id": 92, "name": "Policy-Based Routing Broken", "category": "Advanced", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R1", "gi2", "R2", "gi2")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.22.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0",
                    "access-list 100 permit ip 192.168.1.0 0.0.0.255 any",
                    "route-map PBR permit 10", "match ip address 100", "set ip next-hop 10.0.22.2",
                    "interface loopback0", "ip policy route-map PBR",
                    "ip route 0.0.0.0 0.0.0.0 10.0.12.2"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.22.2 255.255.255.0", "no shutdown",
                    "ip route 192.168.1.0 255.255.255.0 10.0.22.1"],
        },
        "break_config": {"R1": ["no interface loopback0 ip policy route-map PBR",
                                  "interface loopback0", "no ip policy route-map PBR"]},
        "description": "Traffic from 192.168.1.0/24 should go via Gi2 (10.0.22.0/24) but it's using the default route via Gi1 instead. PBR was removed.",
        "hint": "Check if the route-map is applied to the correct interface.",
        "validate": {"R1": ("show run interface loopback0", r"ip policy route-map")},
    },
    {
        "id": 93, "name": "HSRP Priority Wrong", "category": "Advanced", "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "standby 1 ip 10.0.12.254", "standby 1 priority 110", "standby 1 preempt"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "standby 1 ip 10.0.12.254", "standby 1 priority 100"],
        },
        "break_config": {"R1": ["interface gi1", "standby 1 priority 90"]},
        "description": "R1 should be the HSRP active router but R2 is active instead. R1's priority was lowered.",
        "hint": "HSRP highest priority wins. Check priorities on both sides.",
        "validate": {"R1": ("show standby brief", r"Active")},
    },
    {
        "id": 94, "name": "HSRP Authentication Mismatch", "category": "Advanced", "difficulty": 2,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "standby 1 ip 10.0.12.254", "standby 1 authentication cisco"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "standby 1 ip 10.0.12.254", "standby 1 authentication cisco"],
        },
        "break_config": {"R2": ["interface gi1", "standby 1 authentication wrong"]},
        "description": "HSRP shows both routers as Active (split brain). Authentication was changed on R2.",
        "hint": "HSRP authentication must match for routers to see each other.",
        "validate": {"R2": ("show standby | include Authentication", r"cisco")},
    },
    {
        "id": 95, "name": "EtherChannel Mismatch", "category": "Advanced", "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R1", "gi2", "R2", "gi2")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown", "channel-group 1 mode active",
                    "interface gi2", "no shutdown", "channel-group 1 mode active",
                    "interface port-channel1", "ip address 10.0.12.1 255.255.255.0"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown", "channel-group 1 mode passive",
                    "interface gi2", "no shutdown", "channel-group 1 mode passive",
                    "interface port-channel1", "ip address 10.0.12.2 255.255.255.0"],
        },
        "break_config": {"R2": ["interface gi1", "channel-group 1 mode on",
                                  "interface gi2", "channel-group 1 mode on"]},
        "description": "EtherChannel between R1 and R2 is not forming. R1 uses LACP active but R2 was changed.",
        "hint": "LACP active/passive negotiate. Mode 'on' doesn't negotiate and won't form with LACP.",
        "validate": {"R2": ("show etherchannel summary", r"LACP|active|passive")},
    },
    {
        "id": 96, "name": "VRRP Duplicate VIP", "category": "Advanced", "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "vrrp 1 ip 10.0.12.254", "vrrp 1 priority 110"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "vrrp 1 ip 10.0.12.254", "vrrp 1 priority 100"],
        },
        "break_config": {"R2": ["interface gi1", "ip address 10.0.12.254 255.255.255.0"]},
        "description": "IP conflicts on the network. A router has the VIP (10.0.12.254) configured as its real IP, conflicting with VRRP.",
        "hint": "Check if any router has the VIP as its physical interface address.",
        "validate": {"R2": ("show run interface gi1", r"10.0.12.2")},
    },
    {
        "id": 97, "name": "Prefix-List Wrong Mask", "category": "Advanced", "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 172.16.1.1 255.255.255.0",
                    "router bgp 65001", "neighbor 10.0.12.2 remote-as 65002", "network 172.16.1.0 mask 255.255.255.0"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router bgp 65002", "neighbor 10.0.12.1 remote-as 65001",
                    "ip prefix-list ALLOW seq 5 permit 172.16.0.0/16 le 24",
                    "neighbor 10.0.12.1 prefix-list ALLOW in"],
        },
        "break_config": {"R2": ["no ip prefix-list ALLOW seq 5 permit 172.16.0.0/16 le 24",
                                  "ip prefix-list ALLOW seq 5 permit 172.16.0.0/16 ge 25"]},
        "description": "R2 should accept 172.16.1.0/24 from R1 via BGP but the prefix-list is filtering it out.",
        "hint": "Check the prefix-list 'le' and 'ge' modifiers. /24 needs 'le 24' not 'ge 25'.",
        "validate": {"R2": ("show bgp", r"172.16.1.0")},
    },
    {
        "id": 98, "name": "Route-Map Missing Permit", "category": "Advanced", "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface loopback1", "ip address 2.2.2.2 255.255.255.255",
                    "router bgp 65001", "neighbor 10.0.12.2 remote-as 65002",
                    "network 1.1.1.1 mask 255.255.255.255", "network 2.2.2.2 mask 255.255.255.255"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router bgp 65002", "neighbor 10.0.12.1 remote-as 65001"],
        },
        "break_config": {
            "R2": ["access-list 10 permit 1.1.1.1",
                    "route-map FILTER deny 10", "match ip address 10",
                    "router bgp 65002", "neighbor 10.0.12.1 route-map FILTER in"]
        },
        "description": "R2 should block 1.1.1.1/32 but allow 2.2.2.2/32 from R1. Currently both are blocked.",
        "hint": "Route-maps have an implicit deny at the end. You need a permit clause for everything else.",
        "validate": {"R2": ("show bgp", r"2.2.2.2")},
    },
    {
        "id": 99, "name": "TCP MSS Clamping Missing", "category": "Advanced", "difficulty": 3,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1", "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.1 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.2",
                    "ip mtu 1400", "ip tcp adjust-mss 1360"],
            "R2": ["hostname R2", "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface tunnel0", "ip address 172.16.0.2 255.255.255.0",
                    "tunnel source gi1", "tunnel destination 10.0.12.1",
                    "ip mtu 1400", "ip tcp adjust-mss 1360"],
        },
        "break_config": {"R2": ["interface tunnel0", "no ip tcp adjust-mss"]},
        "description": "Web browsing through the tunnel to R2 works for small pages but large pages time out. SSH through the tunnel also hangs.",
        "hint": "When MTU is reduced for tunneling, TCP MSS must also be adjusted to prevent fragmentation issues.",
        "validate": {"R2": ("show run interface tunnel0", r"adjust-mss")},
    },
    {
        "id": 100, "name": "The Full Troubleshoot", "category": "Advanced", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0"],
            "R3": ["hostname R3",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0"],
        },
        "break_config": {
            "R1": ["interface gi1", "shutdown"],
            "R2": ["router ospf 1", "passive-interface gi2"],
            "R3": ["access-list 100 permit tcp any any", "access-list 100 permit udp any any",
                    "access-list 100 permit icmp any any",
                    "interface gi1", "ip access-group 100 in"],
        },
        "description": "Complete network outage. R1 cannot reach R3 (3.3.3.3). There are MULTIPLE issues across the path. Find and fix all of them. This is the final boss.",
        "hint": "Layer by layer: check physical (interfaces up?), then routing (OSPF adjacencies?), then filtering (ACLs blocking protocol 89?).",
        "validate": {"R1": ("ping 3.3.3.3 source 1.1.1.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },

    # ========== CCNP ENCOR/ENARSI: OSPF MULTI-AREA (101-103) ==========
    {
        "id": 101, "name": "OSPF Stub/NSSA Mismatch", "category": "OSPF Multi-Area", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router ospf 1", "router-id 1.1.1.1",
                    "network 10.0.12.0 0.0.0.255 area 0",
                    "network 1.1.1.1 0.0.0.0 area 0",
                    "default-information originate always"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router ospf 1", "router-id 2.2.2.2",
                    "network 10.0.12.0 0.0.0.255 area 0",
                    "network 10.0.23.0 0.0.0.255 area 1",
                    "area 1 stub"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "router ospf 1", "router-id 3.3.3.3",
                    "network 10.0.23.0 0.0.0.255 area 1",
                    "network 3.3.3.3 0.0.0.0 area 1",
                    "area 1 stub"],
        },
        "break_config": {"R2": ["router ospf 1", "no area 1 stub", "area 1 nssa"]},
        "description": "R3 in area 1 has lost all routes and its OSPF adjacency with R2 is down. R3 depends on a stub default route to reach the rest of the network. Something changed on R2's area 1 configuration.",
        "hint": "OSPF area type flags must match between neighbors. Check 'show ip ospf interface' and compare area types on both sides of the link.",
        "validate": {"R3": ("show ip ospf neighbor", r"FULL")},
    },
    {
        "id": 102, "name": "OSPF Inter-Area Summary Black Hole", "category": "OSPF Multi-Area", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 10.1.1.1 255.255.255.0",
                    "interface loopback1", "ip address 10.1.2.1 255.255.255.0",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router ospf 1", "router-id 1.1.1.1",
                    "network 10.1.1.0 0.0.0.255 area 1",
                    "network 10.1.2.0 0.0.0.255 area 1",
                    "network 10.0.12.0 0.0.0.255 area 1"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router ospf 1", "router-id 2.2.2.2",
                    "network 10.0.12.0 0.0.0.255 area 1",
                    "network 10.0.23.0 0.0.0.255 area 0",
                    "area 1 range 10.1.0.0 255.255.0.0"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "router ospf 1", "router-id 3.3.3.3",
                    "network 10.0.23.0 0.0.0.255 area 0",
                    "network 3.3.3.3 0.0.0.0 area 0"],
        },
        "break_config": {"R2": ["router ospf 1", "no area 1 range 10.1.0.0 255.255.0.0",
                                  "area 1 range 10.1.0.0 255.255.0.0 not-advertise"]},
        "description": "R3 can no longer reach any networks in area 1 (10.1.1.0/24, 10.1.2.0/24). R2 is the ABR between area 0 and area 1. The inter-area summarization was recently modified on R2.",
        "hint": "Check R2's OSPF area range configuration. The 'not-advertise' keyword suppresses the summary LSA entirely.",
        "validate": {"R3": ("show ip route ospf", r"10\.1\.")},
    },
    {
        "id": 103, "name": "OSPF Virtual Link Auth Failure", "category": "OSPF Multi-Area", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr"), ("R4", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1"), ("R3", "gi2", "R4", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router ospf 1", "router-id 1.1.1.1",
                    "network 10.0.12.0 0.0.0.255 area 0",
                    "network 1.1.1.1 0.0.0.0 area 0"],
            "R2": ["hostname R2",
                    "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router ospf 1", "router-id 2.2.2.2",
                    "network 10.0.12.0 0.0.0.255 area 0",
                    "network 10.0.23.0 0.0.0.255 area 1",
                    "network 2.2.2.2 0.0.0.0 area 0",
                    "area 1 virtual-link 3.3.3.3 authentication message-digest",
                    "area 1 virtual-link 3.3.3.3 message-digest-key 1 md5 SecretVL"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.34.3 255.255.255.0", "no shutdown",
                    "router ospf 1", "router-id 3.3.3.3",
                    "network 10.0.23.0 0.0.0.255 area 1",
                    "network 10.0.34.0 0.0.0.255 area 2",
                    "network 3.3.3.3 0.0.0.0 area 1",
                    "area 1 virtual-link 2.2.2.2 authentication message-digest",
                    "area 1 virtual-link 2.2.2.2 message-digest-key 1 md5 SecretVL"],
            "R4": ["hostname R4",
                    "interface loopback0", "ip address 4.4.4.4 255.255.255.255",
                    "interface gi1", "ip address 10.0.34.4 255.255.255.0", "no shutdown",
                    "router ospf 1", "router-id 4.4.4.4",
                    "network 10.0.34.0 0.0.0.255 area 2",
                    "network 4.4.4.4 0.0.0.0 area 2"],
        },
        "break_config": {"R3": ["router ospf 1",
                                  "no area 1 virtual-link 2.2.2.2 message-digest-key 1 md5 SecretVL",
                                  "area 1 virtual-link 2.2.2.2 message-digest-key 1 md5 WrongKey"]},
        "description": "R4 in area 2 has lost all inter-area OSPF routes. Area 2 is not directly connected to area 0 — it relies on a virtual link through area 1 between R2 and R3. The virtual link was working yesterday but is now down.",
        "hint": "Virtual links require matching authentication. Check 'show ip ospf virtual-links' on both R2 and R3. Compare MD5 keys.",
        "validate": {"R4": ("show ip route ospf", r"1\.1\.1\.1")},
    },

    # ========== CCNP ENCOR/ENARSI: BGP ADVANCED (104-107) ==========
    {
        "id": 104, "name": "BGP Route Reflector Not Reflecting", "category": "BGP Advanced", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0",
                    "router bgp 65001",
                    "bgp router-id 1.1.1.1",
                    "neighbor 2.2.2.2 remote-as 65001",
                    "neighbor 2.2.2.2 update-source loopback0",
                    "network 192.168.1.0 mask 255.255.255.0",
                    "ip route 192.168.1.0 255.255.255.0 Null0"],
            "R2": ["hostname R2",
                    "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0",
                    "router bgp 65001",
                    "bgp router-id 2.2.2.2",
                    "neighbor 1.1.1.1 remote-as 65001",
                    "neighbor 1.1.1.1 update-source loopback0",
                    "neighbor 1.1.1.1 route-reflector-client",
                    "neighbor 3.3.3.3 remote-as 65001",
                    "neighbor 3.3.3.3 update-source loopback0",
                    "neighbor 3.3.3.3 route-reflector-client"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0",
                    "router bgp 65001",
                    "bgp router-id 3.3.3.3",
                    "neighbor 2.2.2.2 remote-as 65001",
                    "neighbor 2.2.2.2 update-source loopback0"],
        },
        "break_config": {"R2": ["router bgp 65001",
                                  "no neighbor 3.3.3.3 route-reflector-client"]},
        "description": "R3 is not receiving 192.168.1.0/24 from R1 via BGP. All three routers are iBGP AS 65001. R2 is supposed to be the route reflector. BGP sessions are up but R3's BGP table is empty.",
        "hint": "iBGP split-horizon: a route learned from an iBGP peer is not advertised to another iBGP peer unless the router is a route reflector for that client. Check R2's neighbor configuration.",
        "validate": {"R3": ("show bgp 192.168.1.0", r"192\.168\.1\.0")},
    },
    {
        "id": 105, "name": "BGP Confederation Peer Mismatch", "category": "BGP Advanced", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router bgp 65001",
                    "bgp router-id 1.1.1.1",
                    "bgp confederation identifier 65099",
                    "bgp confederation peers 65002",
                    "neighbor 10.0.12.2 remote-as 65001",
                    "network 192.168.1.0 mask 255.255.255.0",
                    "ip route 192.168.1.0 255.255.255.0 Null0"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router bgp 65001",
                    "bgp router-id 2.2.2.2",
                    "bgp confederation identifier 65099",
                    "bgp confederation peers 65002",
                    "neighbor 10.0.12.1 remote-as 65001",
                    "neighbor 10.0.23.3 remote-as 65002"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "router bgp 65002",
                    "bgp router-id 3.3.3.3",
                    "bgp confederation identifier 65099",
                    "bgp confederation peers 65001",
                    "neighbor 10.0.23.2 remote-as 65001",
                    "network 3.3.3.3 mask 255.255.255.255"],
        },
        "break_config": {"R3": ["router bgp 65002",
                                  "no bgp confederation peers 65001"]},
        "description": "R1 cannot see R3's loopback (3.3.3.3) via BGP. The network uses confederation AS 65099 with sub-AS 65001 (R1,R2) and 65002 (R3). The BGP session between R2 and R3 is established but routes are not being exchanged properly.",
        "hint": "In a confederation, each sub-AS must declare the other sub-AS numbers as confederation peers. Without this, the router treats the neighbor as a true eBGP peer with different behavior. Check 'show bgp summary' and 'bgp confederation peers' on R3.",
        "validate": {"R1": ("show bgp 3.3.3.3", r"3\.3\.3\.3")},
    },
    {
        "id": 106, "name": "BGP Community No-Export Blocking", "category": "BGP Advanced", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0",
                    "router bgp 65001",
                    "neighbor 10.0.12.2 remote-as 65002",
                    "network 192.168.1.0 mask 255.255.255.0"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router bgp 65002",
                    "neighbor 10.0.12.1 remote-as 65001",
                    "neighbor 10.0.23.3 remote-as 65002",
                    "neighbor 10.0.23.3 route-reflector-client",
                    "neighbor 10.0.12.1 send-community"],
            "R3": ["hostname R3",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "router bgp 65002",
                    "neighbor 10.0.23.2 remote-as 65002"],
        },
        "break_config": {"R1": ["route-map SET_COMMUNITY permit 10",
                                  "set community no-export",
                                  "router bgp 65001",
                                  "neighbor 10.0.12.2 route-map SET_COMMUNITY out",
                                  "neighbor 10.0.12.2 send-community"]},
        "description": "R3 is not receiving 192.168.1.0/24 from R1. R2 has the route in its BGP table but is not advertising it to R3. The BGP sessions are all established. R1's outbound policy was recently changed.",
        "hint": "The no-export community prevents a route from being advertised to eBGP peers. But in this topology R2-R3 are iBGP — so check: is no-export also blocking iBGP advertisement? Actually, no-export blocks advertisement outside the local AS. Check communities on R2: 'show bgp 192.168.1.0'. The real issue might be that R2 treats reflected routes with no-export as non-exportable beyond the confederation/AS boundary.",
        "validate": {"R3": ("show bgp 192.168.1.0", r"192\.168\.1\.0")},
    },
    {
        "id": 107, "name": "BGP AS-Path Prepend Backfire", "category": "BGP Advanced", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R1", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.13.1 255.255.255.0", "no shutdown",
                    "router bgp 65001",
                    "neighbor 10.0.12.2 remote-as 65002",
                    "neighbor 10.0.13.3 remote-as 65002"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 10.0.200.1 255.255.255.0",
                    "router bgp 65002",
                    "neighbor 10.0.12.1 remote-as 65001",
                    "network 10.0.200.0 mask 255.255.255.0"],
            "R3": ["hostname R3",
                    "interface gi1", "ip address 10.0.13.3 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 10.0.200.1 255.255.255.0",
                    "router bgp 65002",
                    "neighbor 10.0.13.1 remote-as 65001",
                    "network 10.0.200.0 mask 255.255.255.0"],
        },
        "break_config": {"R2": ["route-map SET_MED permit 10",
                                  "set as-path prepend 65002 65002 65002",
                                  "set metric 9999",
                                  "router bgp 65002",
                                  "neighbor 10.0.12.1 route-map SET_MED out"]},
        "description": "R1 should prefer the path to 10.0.200.0/24 via R2 (10.0.12.2) as the primary link. Currently R1 is routing via R3 instead. Someone added AS-path prepending and MED on R2 to 'deprioritize' it during maintenance but forgot to remove it. R2 is the preferred path.",
        "hint": "Check R1's BGP table: 'show bgp 10.0.200.0'. Compare the AS-path length and MED for both paths. The route-map on R2's outbound policy is artificially making R2's path look worse.",
        "validate": {"R1": ("show ip route 10.0.200.0", r"10\.0\.12\.2")},
    },

    # ========== CCNP ENCOR/ENARSI: REDISTRIBUTION COMPLEX (108-110) ==========
    {
        "id": 108, "name": "Mutual Redistribution Feedback Loop", "category": "Redistribution", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1"), ("R3", "gi2", "R1", "gi2")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.31.1 255.255.255.0", "no shutdown",
                    "router ospf 1",
                    "network 10.0.12.0 0.0.0.255 area 0",
                    "network 1.1.1.1 0.0.0.0 area 0",
                    "router eigrp 100",
                    "network 10.0.31.0 0.0.0.255",
                    "redistribute ospf 1 metric 10000 100 255 1 1500 route-map TAG_ROUTES"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.31.3 255.255.255.0", "no shutdown",
                    "router ospf 1",
                    "network 10.0.23.0 0.0.0.255 area 0",
                    "network 3.3.3.3 0.0.0.0 area 0",
                    "redistribute eigrp 100 subnets route-map TAG_ROUTES",
                    "router eigrp 100",
                    "network 10.0.31.0 0.0.0.255"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router ospf 1",
                    "network 10.0.12.0 0.0.0.255 area 0",
                    "network 10.0.23.0 0.0.0.255 area 0"],
        },
        "break_config": {
            "R1": ["no route-map TAG_ROUTES",
                    "route-map TAG_ROUTES permit 10", "set tag 110",
                    "router eigrp 100",
                    "redistribute ospf 1 metric 10000 100 255 1 1500"],
            "R3": ["no route-map TAG_ROUTES",
                    "router ospf 1",
                    "redistribute eigrp 100 subnets"],
        },
        "description": "After a change window, R2 is seeing duplicate routes to several networks with different metrics and types (OSPF internal vs external). R1 redistributes OSPF into EIGRP, R3 redistributes EIGRP into OSPF. Routes are feeding back — OSPF routes go to EIGRP on R1, come back as OSPF external on R3.",
        "hint": "Mutual redistribution needs anti-feedback filtering. Use route tags: tag routes when redistributing, deny tagged routes when redistributing back. Check R1 and R3's redistribution route-maps.",
        "validate": {"R2": ("show ip route 10.0.31.0", r"O |10\.0\.31\.0")},
    },
    {
        "id": 109, "name": "EIGRP Redistribution Missing Seed Metric", "category": "Redistribution", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router ospf 1",
                    "network 10.0.12.0 0.0.0.255 area 0",
                    "network 1.1.1.1 0.0.0.0 area 0",
                    "redistribute eigrp 100 subnets"],
            "R2": ["hostname R2",
                    "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "router eigrp 100",
                    "network 10.0.12.0 0.0.0.255",
                    "network 2.2.2.2 0.0.0.0",
                    "redistribute ospf 1 metric 10000 100 255 1 1500",
                    "router ospf 1",
                    "network 10.0.12.0 0.0.0.255 area 0"],
        },
        "break_config": {"R2": ["router eigrp 100",
                                  "no redistribute ospf 1 metric 10000 100 255 1 1500",
                                  "redistribute ospf 1"]},
        "description": "R2 is running EIGRP 100 and OSPF 1 with mutual redistribution. R2 can see R1's loopback (1.1.1.1) in OSPF but the route is not appearing in EIGRP's routing table. OSPF-to-EIGRP redistribution appears to be broken on R2.",
        "hint": "EIGRP requires a seed metric (bandwidth, delay, reliability, load, MTU) for redistributed routes. Without one, the metric is infinity and routes are not installed. Check R2's EIGRP redistribution command.",
        "validate": {"R2": ("show ip route eigrp", r"1\.1\.1\.1")},
    },
    {
        "id": 110, "name": "Redistribution Route Tag Filtering Gone Wrong", "category": "Redistribution", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router ospf 1",
                    "network 10.0.12.0 0.0.0.255 area 0",
                    "router eigrp 200",
                    "network 10.0.23.0 0.0.0.255",
                    "route-map REDIST_EIGRP deny 10", "match tag 220",
                    "route-map REDIST_EIGRP permit 20", "set tag 110",
                    "route-map REDIST_OSPF deny 10", "match tag 110",
                    "route-map REDIST_OSPF permit 20", "set tag 220",
                    "redistribute eigrp 200 subnets route-map REDIST_EIGRP",
                    "redistribute ospf 1 metric 10000 100 255 1 1500 route-map REDIST_OSPF"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "router eigrp 200",
                    "network 10.0.23.0 0.0.0.255",
                    "network 3.3.3.3 0.0.0.0"],
        },
        "break_config": {"R2": ["no route-map REDIST_EIGRP deny 10",
                                  "no route-map REDIST_EIGRP permit 20",
                                  "route-map REDIST_EIGRP deny 10", "match tag 110",
                                  "route-map REDIST_EIGRP permit 20",
                                  "no route-map REDIST_OSPF deny 10",
                                  "no route-map REDIST_OSPF permit 20",
                                  "route-map REDIST_OSPF permit 10"]},
        "description": "R1 should see R3's loopback (3.3.3.3) via OSPF external, and R3 should see R1's loopback (1.1.1.1) via EIGRP. R2 does mutual redistribution with route-tag filtering to prevent loops. After a recent change, the tag filtering is wrong — tags are swapped or missing, causing routes to be incorrectly denied or fed back.",
        "hint": "Route-map logic: when redistributing OSPF into EIGRP, deny routes tagged 220 (EIGRP-originated) and set tag 110. When redistributing EIGRP into OSPF, deny routes tagged 110 (OSPF-originated) and set tag 220. Check the deny/permit clauses and tags.",
        "validate": {
            "R1": ("show ip route 3.3.3.3", r"3\.3\.3\.3"),
            "R3": ("show ip route 1.1.1.1", r"1\.1\.1\.1"),
        },
    },

    # ========== CCNP ENCOR/ENARSI: VRF / VRF-LITE (111-113) ==========
    {
        "id": 111, "name": "VRF Route Leak Missing", "category": "VRF", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "ip route 192.168.10.0 255.255.255.0 10.0.12.2"],
            "R2": ["hostname R2",
                    "vrf definition CUSTOMER_A",
                    "address-family ipv4", "exit-address-family",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "vrf forwarding CUSTOMER_A",
                    "ip address 192.168.10.1 255.255.255.0",
                    "ip route vrf CUSTOMER_A 0.0.0.0 0.0.0.0 10.0.12.1 global",
                    "ip route 192.168.10.0 255.255.255.0 Loopback0 global"],
        },
        "break_config": {"R2": ["no ip route vrf CUSTOMER_A 0.0.0.0 0.0.0.0 10.0.12.1 global",
                                  "no ip route 192.168.10.0 255.255.255.0 Loopback0 global"]},
        "description": "R1 cannot reach 192.168.10.0/24 on R2's VRF CUSTOMER_A. The VRF interface is up and R2 can ping 192.168.10.1 from within the VRF, but traffic from R1 never reaches it. Route leaking between VRF and global table was recently removed on R2.",
        "hint": "VRF traffic is isolated from the global routing table by default. Static routes with the 'global' keyword are needed to leak traffic between VRF and global. Check R2's routing table and VRF routing table.",
        "validate": {"R1": ("ping 192.168.10.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 112, "name": "VRF Interface Assignment Dropped Routes", "category": "VRF", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 192.168.10.1 255.255.255.0",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 0.0.0.0"],
            "R2": ["hostname R2",
                    "vrf definition CUSTOMER_A",
                    "address-family ipv4", "exit-address-family",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 0.0.0.0"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 192.168.20.1 255.255.255.0",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "router eigrp 100", "network 0.0.0.0"],
        },
        "break_config": {"R2": ["interface gi2", "vrf forwarding CUSTOMER_A",
                                  "ip address 10.0.23.2 255.255.255.0"]},
        "description": "R1 can no longer reach R3 (192.168.20.1) through R2. R2 is the only path. EIGRP adjacency between R2 and R3 is down. Someone assigned R2's gi2 interface to a VRF, which silently stripped the IP address and moved the interface out of the global routing table.",
        "hint": "Assigning an interface to a VRF removes its IP address from the global table. Check 'show vrf' on R2 and 'show ip interface brief'. The interface might be in a VRF while EIGRP is running in the global table.",
        "validate": {"R1": ("ping 192.168.20.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 113, "name": "VRF EIGRP Address Family Missing", "category": "VRF", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "vrf definition CUSTOMER_A",
                    "address-family ipv4", "exit-address-family",
                    "interface loopback0", "vrf forwarding CUSTOMER_A",
                    "ip address 192.168.10.1 255.255.255.0",
                    "interface gi1", "vrf forwarding CUSTOMER_A",
                    "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router eigrp NAMED",
                    "address-family ipv4 vrf CUSTOMER_A autonomous-system 100",
                    "network 0.0.0.0", "exit-address-family"],
            "R2": ["hostname R2",
                    "vrf definition CUSTOMER_A",
                    "address-family ipv4", "exit-address-family",
                    "interface gi1", "vrf forwarding CUSTOMER_A",
                    "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "vrf forwarding CUSTOMER_A",
                    "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router eigrp NAMED",
                    "address-family ipv4 vrf CUSTOMER_A autonomous-system 100",
                    "network 0.0.0.0", "exit-address-family"],
            "R3": ["hostname R3",
                    "vrf definition CUSTOMER_A",
                    "address-family ipv4", "exit-address-family",
                    "interface loopback0", "vrf forwarding CUSTOMER_A",
                    "ip address 192.168.20.1 255.255.255.0",
                    "interface gi1", "vrf forwarding CUSTOMER_A",
                    "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "router eigrp NAMED",
                    "address-family ipv4 vrf CUSTOMER_A autonomous-system 100",
                    "network 0.0.0.0", "exit-address-family"],
        },
        "break_config": {"R2": ["router eigrp NAMED",
                                  "no address-family ipv4 vrf CUSTOMER_A autonomous-system 100"]},
        "description": "R1 (192.168.10.0/24) cannot reach R3 (192.168.20.0/24). All interfaces are in VRF CUSTOMER_A and show up/up. EIGRP named mode is used with VRF address families. R2's EIGRP VRF address family was accidentally removed during a config change.",
        "hint": "Named EIGRP uses 'address-family ipv4 vrf X autonomous-system Y' to run EIGRP within a VRF. Check R2's EIGRP configuration. Without the address family, R2 has no routing protocol for the VRF.",
        "validate": {"R1": ("ping vrf CUSTOMER_A 192.168.20.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },

    # ========== CCNP ENCOR/ENARSI: DMVPN / OVERLAY (114-115) ==========
    {
        "id": 114, "name": "DMVPN Phase 3 No Spoke-to-Spoke", "category": "DMVPN", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R1", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname HUB",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.13.1 255.255.255.0", "no shutdown",
                    "interface tunnel0",
                    "ip address 172.16.0.1 255.255.255.0",
                    "ip nhrp network-id 1",
                    "ip nhrp redirect",
                    "tunnel source gi1",
                    "tunnel mode gre multipoint",
                    "tunnel key 100",
                    "ip mtu 1400",
                    "ip tcp adjust-mss 1360",
                    "router eigrp 100",
                    "network 172.16.0.0 0.0.0.255",
                    "no auto-summary"],
            "R2": ["hostname SPOKE1",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.10.1 255.255.255.0",
                    "interface tunnel0",
                    "ip address 172.16.0.2 255.255.255.0",
                    "ip nhrp network-id 1",
                    "ip nhrp nhs 172.16.0.1 nbma 10.0.12.1",
                    "ip nhrp shortcut",
                    "tunnel source gi1",
                    "tunnel mode gre multipoint",
                    "tunnel key 100",
                    "ip mtu 1400",
                    "ip tcp adjust-mss 1360",
                    "router eigrp 100",
                    "network 172.16.0.0 0.0.0.255",
                    "network 192.168.10.0 0.0.0.255",
                    "no auto-summary"],
            "R3": ["hostname SPOKE2",
                    "interface gi1", "ip address 10.0.13.3 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.20.1 255.255.255.0",
                    "interface tunnel0",
                    "ip address 172.16.0.3 255.255.255.0",
                    "ip nhrp network-id 1",
                    "ip nhrp nhs 172.16.0.1 nbma 10.0.13.1",
                    "ip nhrp shortcut",
                    "tunnel source gi1",
                    "tunnel mode gre multipoint",
                    "tunnel key 100",
                    "ip mtu 1400",
                    "ip tcp adjust-mss 1360",
                    "router eigrp 100",
                    "network 172.16.0.0 0.0.0.255",
                    "network 192.168.20.0 0.0.0.255",
                    "no auto-summary"],
        },
        "break_config": {"R1": ["interface tunnel0", "no ip nhrp redirect"]},
        "description": "Spoke-to-spoke traffic between SPOKE1 (192.168.10.0/24) and SPOKE2 (192.168.20.0/24) is hairpinning through the hub instead of building direct tunnels. Hub-to-spoke connectivity works fine. This is DMVPN Phase 3 — spoke-to-spoke shortcuts should form automatically.",
        "hint": "Phase 3 DMVPN requires 'ip nhrp redirect' on the hub to send traffic indication messages, and 'ip nhrp shortcut' on spokes. Check the hub's tunnel0 configuration.",
        "validate": {"R2": ("ping 192.168.20.1 source 192.168.10.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 115, "name": "DMVPN NHRP Registration Failure", "category": "DMVPN", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr")],
        "links": [("R1", "gi1", "R2", "gi1")],
        "base_config": {
            "R1": ["hostname HUB",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface tunnel0",
                    "ip address 172.16.0.1 255.255.255.0",
                    "ip nhrp network-id 1",
                    "ip nhrp authentication DMVPNKEY",
                    "tunnel source gi1",
                    "tunnel mode gre multipoint",
                    "tunnel key 100"],
            "R2": ["hostname SPOKE",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.10.1 255.255.255.0",
                    "interface tunnel0",
                    "ip address 172.16.0.2 255.255.255.0",
                    "ip nhrp network-id 1",
                    "ip nhrp authentication DMVPNKEY",
                    "ip nhrp nhs 172.16.0.1 nbma 10.0.12.1",
                    "tunnel source gi1",
                    "tunnel mode gre multipoint",
                    "tunnel key 100"],
        },
        "break_config": {"R2": ["interface tunnel0",
                                  "no ip nhrp authentication DMVPNKEY",
                                  "ip nhrp authentication WRONGKEY",
                                  "no tunnel key 100",
                                  "tunnel key 200"]},
        "description": "The spoke (SPOKE) cannot register with the hub. Tunnel interfaces are up on both sides but NHRP mapping is empty on the hub. The spoke was recently reconfigured and two NHRP parameters were changed.",
        "hint": "NHRP authentication string and tunnel key must match between hub and spoke. Check both values on the spoke vs hub: 'show ip nhrp' and 'show run interface tunnel0'.",
        "validate": {"R1": ("show ip nhrp", r"172\.16\.0\.2.*10\.0\.12\.2|10\.0\.12\.2.*NBMA")},
    },

    # ========== CCNP ENCOR/ENARSI: MULTI-PROTOCOL MULTI-FAULT (116-120) ==========
    {
        "id": 116, "name": "OSPF Passive + ACL Protocol 89 Block", "category": "Multi-Fault", "difficulty": 4,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0"],
        },
        "break_config": {
            "R2": ["router ospf 1", "passive-interface gi2"],
            "R3": ["access-list 101 permit tcp any any",
                    "access-list 101 permit udp any any",
                    "access-list 101 permit icmp any any",
                    "interface gi1", "ip access-group 101 in"],
        },
        "description": "R1 cannot reach R3's loopback (3.3.3.3). There are TWO separate issues preventing OSPF adjacency between R2 and R3. Fix both to restore connectivity.",
        "hint": "Fault 1: Check R2's OSPF passive interfaces. Fault 2: The ACL on R3 permits TCP/UDP/ICMP but what protocol does OSPF use? It's IP protocol 89, not TCP or UDP.",
        "validate": {"R1": ("ping 3.3.3.3 source 1.1.1.1 repeat 3", r"[Ss]uccess rate is [6-9][0-9]|100 percent")},
    },
    {
        "id": 117, "name": "iBGP Unreachable Loopback + Wrong Update Source", "category": "Multi-Fault", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0",
                    "router bgp 65001",
                    "neighbor 2.2.2.2 remote-as 65001",
                    "neighbor 2.2.2.2 update-source loopback0",
                    "network 192.168.1.0 mask 255.255.255.0",
                    "ip route 192.168.1.0 255.255.255.0 Null0"],
            "R2": ["hostname R2",
                    "interface loopback0", "ip address 2.2.2.2 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0",
                    "router bgp 65001",
                    "neighbor 1.1.1.1 remote-as 65001",
                    "neighbor 1.1.1.1 update-source loopback0",
                    "neighbor 1.1.1.1 route-reflector-client",
                    "neighbor 3.3.3.3 remote-as 65001",
                    "neighbor 3.3.3.3 update-source loopback0",
                    "neighbor 3.3.3.3 route-reflector-client"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0",
                    "router bgp 65001",
                    "neighbor 2.2.2.2 remote-as 65001",
                    "neighbor 2.2.2.2 update-source loopback0"],
        },
        "break_config": {
            "R2": ["router ospf 1", "no network 10.0.23.0 0.0.0.255 area 0"],
            "R3": ["router bgp 65001",
                    "no neighbor 2.2.2.2 update-source loopback0",
                    "neighbor 2.2.2.2 update-source gi1"],
        },
        "description": "R3 is not receiving BGP routes from R1. The iBGP session between R2 and R3 is not establishing. There are TWO issues: one at the IGP layer and one at the BGP layer. Both must be fixed for R3 to receive routes.",
        "hint": "Fault 1: R3's loopback must be reachable from R2 via OSPF for the iBGP session. Check OSPF on the R2-R3 link. Fault 2: Even with IGP fixed, the BGP update-source on R3 must match what R2 expects. Check 'neighbor update-source' on R3.",
        "validate": {"R3": ("show bgp 192.168.1.0", r"192\.168\.1\.0")},
    },
    {
        "id": 118, "name": "OSPF MTU + Redistribution Metric + EIGRP Auth Triple Fault", "category": "Multi-Fault", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 1.1.1.1 255.255.255.255",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 0.0.0.0 255.255.255.255 area 0"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "key chain EIGRP_KEY", "key 1", "key-string SecretEIGRP",
                    "router ospf 1", "network 10.0.12.0 0.0.0.255 area 0",
                    "redistribute eigrp 100 subnets",
                    "router eigrp 100", "network 10.0.23.0 0.0.0.255",
                    "redistribute ospf 1 metric 10000 100 255 1 1500",
                    "interface gi2", "ip authentication mode eigrp 100 md5",
                    "ip authentication key-chain eigrp 100 EIGRP_KEY"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "key chain EIGRP_KEY", "key 1", "key-string SecretEIGRP",
                    "router eigrp 100", "network 0.0.0.0",
                    "interface gi1", "ip authentication mode eigrp 100 md5",
                    "ip authentication key-chain eigrp 100 EIGRP_KEY"],
        },
        "break_config": {
            "R1": ["interface gi1", "ip mtu 1400"],
            "R2": ["router eigrp 100",
                    "no redistribute ospf 1 metric 10000 100 255 1 1500",
                    "redistribute ospf 1"],
            "R3": ["no key chain EIGRP_KEY",
                    "key chain EIGRP_KEY", "key 1", "key-string WrongPassword"],
        },
        "description": "Complete end-to-end failure: R1 cannot reach R3 (3.3.3.3) and R3 cannot reach R1 (1.1.1.1). There are THREE separate faults across different protocol layers. This requires systematic troubleshooting from Layer 1 up.",
        "hint": "Fault 1: OSPF adjacency between R1 and R2 — check MTU. Fault 2: EIGRP redistribution on R2 — check seed metrics. Fault 3: EIGRP adjacency between R2 and R3 — check authentication.",
        "validate": {
            "R1": ("show ip ospf neighbor", r"FULL"),
            "R3": ("show ip route eigrp", r"1\.1\.1\.1"),
        },
    },
    {
        "id": 119, "name": "BGP Prefix-List + Redistribution + Static Null0 Cascade", "category": "Multi-Fault", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr"), ("R4", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1"), ("R3", "gi2", "R4", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0",
                    "router bgp 65001",
                    "neighbor 10.0.12.2 remote-as 65002",
                    "network 192.168.1.0 mask 255.255.255.0"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "router bgp 65002",
                    "neighbor 10.0.12.1 remote-as 65001",
                    "router ospf 1",
                    "network 10.0.23.0 0.0.0.255 area 0",
                    "redistribute bgp 65002 subnets",
                    "router bgp 65002",
                    "redistribute ospf 1"],
            "R3": ["hostname R3",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.34.3 255.255.255.0", "no shutdown",
                    "router ospf 1", "network 10.0.23.0 0.0.0.255 area 0",
                    "router eigrp 100", "network 10.0.34.0 0.0.0.255",
                    "redistribute ospf 1 metric 10000 100 255 1 1500"],
            "R4": ["hostname R4",
                    "interface gi1", "ip address 10.0.34.4 255.255.255.0", "no shutdown",
                    "interface loopback0", "ip address 4.4.4.4 255.255.255.255",
                    "router eigrp 100", "network 0.0.0.0"],
        },
        "break_config": {
            "R2": ["ip prefix-list BGP_IN deny 192.168.1.0/24",
                    "ip prefix-list BGP_IN permit 0.0.0.0/0 le 32",
                    "router bgp 65002", "neighbor 10.0.12.1 prefix-list BGP_IN in"],
            "R3": ["router eigrp 100",
                    "no redistribute ospf 1 metric 10000 100 255 1 1500",
                    "redistribute ospf 1"],
            "R4": ["ip route 192.168.1.0 255.255.255.0 Null0"],
        },
        "description": "R4 cannot reach R1's network 192.168.1.0/24. The path is R1(BGP)→R2(OSPF)→R3(EIGRP)→R4. There are THREE separate faults in the forwarding chain. Each one alone would break reachability.",
        "hint": "Fault 1: Check R2's BGP inbound filtering — is it accepting 192.168.1.0/24? Fault 2: Check R3's EIGRP redistribution — does EIGRP have a seed metric? Fault 3: Check R4's routing table — is there a more specific or equal static route overriding EIGRP?",
        "validate": {"R4": ("show ip route 192.168.1.0", r"D EX|D\*EX|EX.*192\.168\.1\.0")},
    },
    {
        "id": 120, "name": "The CCNP Final Boss — Triple Protocol Meltdown", "category": "Multi-Fault", "difficulty": 5,
        "devices": [("R1", "csr"), ("R2", "csr"), ("R3", "csr"), ("R4", "csr")],
        "links": [("R1", "gi1", "R2", "gi1"), ("R2", "gi2", "R3", "gi1"), ("R2", "gi3", "R4", "gi1")],
        "base_config": {
            "R1": ["hostname R1",
                    "interface loopback0", "ip address 192.168.1.1 255.255.255.0",
                    "interface gi1", "ip address 10.0.12.1 255.255.255.0", "no shutdown",
                    "router bgp 65001",
                    "neighbor 10.0.12.2 remote-as 65002",
                    "network 192.168.1.0 mask 255.255.255.0"],
            "R2": ["hostname R2",
                    "interface gi1", "ip address 10.0.12.2 255.255.255.0", "no shutdown",
                    "interface gi2", "ip address 10.0.23.2 255.255.255.0", "no shutdown",
                    "interface gi3", "ip address 10.0.24.2 255.255.255.0", "no shutdown",
                    "router bgp 65002",
                    "neighbor 10.0.12.1 remote-as 65001",
                    "redistribute ospf 1", "redistribute eigrp 100",
                    "router ospf 1",
                    "network 10.0.23.0 0.0.0.255 area 0",
                    "redistribute bgp 65002 subnets",
                    "area 1 stub",
                    "key chain EIGRP_KEY", "key 1", "key-string CorrectKey",
                    "router eigrp 100",
                    "network 10.0.24.0 0.0.0.255",
                    "redistribute bgp 65002 metric 10000 100 255 1 1500",
                    "redistribute ospf 1 metric 10000 100 255 1 1500",
                    "interface gi3", "ip authentication mode eigrp 100 md5",
                    "ip authentication key-chain eigrp 100 EIGRP_KEY"],
            "R3": ["hostname R3",
                    "interface loopback0", "ip address 3.3.3.3 255.255.255.255",
                    "interface gi1", "ip address 10.0.23.3 255.255.255.0", "no shutdown",
                    "router ospf 1",
                    "network 0.0.0.0 255.255.255.255 area 0"],
            "R4": ["hostname R4",
                    "interface loopback0", "ip address 4.4.4.4 255.255.255.255",
                    "interface gi1", "ip address 10.0.24.4 255.255.255.0", "no shutdown",
                    "key chain EIGRP_KEY", "key 1", "key-string CorrectKey",
                    "router eigrp 100", "network 0.0.0.0",
                    "interface gi1", "ip authentication mode eigrp 100 md5",
                    "ip authentication key-chain eigrp 100 EIGRP_KEY"],
        },
        "break_config": {
            "R2": ["router ospf 1", "passive-interface gi2",
                    "route-map BLOCK_ALL deny 10",
                    "router bgp 65002", "neighbor 10.0.12.1 route-map BLOCK_ALL out"],
            "R3": ["router ospf 1", "area 0 authentication message-digest",
                    "interface gi1", "ip ospf message-digest-key 1 md5 UnknownPW"],
            "R4": ["no key chain EIGRP_KEY",
                    "key chain EIGRP_KEY", "key 1", "key-string WrongKey"],
        },
        "description": "Total meltdown. R1 cannot receive any routes from R2. R3 (OSPF) and R4 (EIGRP) are both unreachable from R1. R2 is the central hub connecting all three protocols. There are THREE simultaneous faults — one per protocol domain (BGP, OSPF, EIGRP). Systematic troubleshooting required.",
        "hint": "Start at R2 and work outward. Fault 1 (BGP): Check R2's outbound policy to R1 — is a route-map blocking everything? Fault 2 (OSPF): Check R2-R3 OSPF adjacency — is it forming? Check passive-interface AND authentication. Fault 3 (EIGRP): Check R2-R4 EIGRP adjacency — compare authentication key-chains.",
        "validate": {
            "R1": ("show bgp 3.3.3.3", r"3\.3\.3\.3"),
            "R3": ("show ip ospf neighbor", r"FULL"),
            "R4": ("show ip route eigrp", r"192\.168\.1\.0|10\.0\.23\.0"),
        },
    },
]


def reset_device_config(lab, name):
    """Wipe a running device back to a clean state via console. Keeps the device running."""
    node = lab._find_node(name)
    if not node or node["status"] != "started" or not node.get("console"):
        return False

    try:
        console = DeviceConsole(port=node["console"])
        if not console.connect():
            return False

        # Exit any mode we might be in
        console.send("end", wait=0.5)
        console.send("enable", wait=1)
        console.send("", wait=0.5)

        # Nuke the running config and replace with minimal baseline
        # Using 'configure replace' if available, otherwise manual wipe

        # First try the fast way: write a clean config to flash and replace
        console.send("configure terminal", wait=0.5)

        # Remove VRFs (must come before interface cleanup)
        for vrf in ["CUSTOMER_A", "CUSTOMER_B"]:
            console.send(f"no vrf definition {vrf}", wait=0.3)

        # Remove routing protocols (all common ASNs)
        for proto in [
            "no router ospf 1", "no router ospf 2",
            "no router eigrp 100", "no router eigrp 200",
            "no router eigrp NAMED",
            "no router bgp 65001", "no router bgp 65002", "no router bgp 65099",
        ]:
            console.send(proto, wait=0.2)

        # Remove all static routes
        console.send("end", wait=0.3)
        console.send("show ip route static", wait=1)
        console.send("configure terminal", wait=0.3)
        for prefix in [
            "0.0.0.0", "1.1.1.1", "2.2.2.2", "3.3.3.3",
            "10.0.0.0", "10.0.12.0", "10.0.13.0", "10.0.20.0", "10.0.22.0",
            "10.0.23.0", "10.0.31.0", "10.0.99.0", "10.1.0.0", "10.2.0.0",
            "172.16.0.0", "192.168.1.0", "192.168.2.0",
            "10.0.13.0", "10.0.14.0", "10.0.24.0", "10.0.34.0",
            "10.0.200.0", "10.1.0.0", "10.1.1.0", "10.1.2.0",
            "192.168.10.0", "192.168.20.0", "4.4.4.4",
        ]:
            console.send(f"no ip route {prefix} 0.0.0.0 0.0.0.0", wait=0.1)
            console.send(f"no ip route {prefix} 255.255.255.0", wait=0.1)
            console.send(f"no ip route {prefix} 255.255.255.255", wait=0.1)
            console.send(f"no ip route {prefix} 255.255.0.0", wait=0.1)
            console.send(f"no ip route {prefix} 255.0.0.0", wait=0.1)

        # Default all interfaces (resets IP, shutdown state, everything)
        for i in range(1, 5):
            console.send(f"default interface GigabitEthernet{i}", wait=0.3)
        console.send("default interface Loopback0", wait=0.2)
        console.send("default interface Loopback1", wait=0.2)
        console.send("no interface Loopback0", wait=0.2)
        console.send("no interface Loopback1", wait=0.2)
        console.send("no interface Tunnel0", wait=0.2)
        console.send("no interface Tunnel1", wait=0.2)
        console.send("no interface Port-channel1", wait=0.2)

        # Remove ACLs
        for n in [1, 5, 10, 100, 101, 102]:
            console.send(f"no access-list {n}", wait=0.1)
        for name_acl in [
            "ALLOW_R2", "TIMED_ACL", "ALLOW", "DENY_ALL",
            "NHRP_ALLOW", "MATCH_ROUTES",
        ]:
            console.send(f"no ip access-list extended {name_acl}", wait=0.1)
            console.send(f"no ip access-list standard {name_acl}", wait=0.1)

        # Remove prefix-lists
        for pl in ["ALLOW", "DENY_ALL", "OSPF_FILTER", "BGP_IN", "BGP_OUT", "REDIST_FILTER"]:
            console.send(f"no ip prefix-list {pl}", wait=0.1)

        # Remove route-maps
        for rm in [
            "FILTER", "BLOCK_ALL", "TAG_BLACKHOLE", "PBR",
            "BLOCK_R2", "ALLOW_R2",
            "SET_COMMUNITY", "SET_MED", "SET_LOCAL_PREF",
            "REDIST_OSPF", "REDIST_EIGRP", "TAG_ROUTES", "LEAK_ROUTES",
        ]:
            console.send(f"no route-map {rm}", wait=0.1)

        # Remove NAT
        console.send("no ip nat inside source list 1 interface GigabitEthernet1 overload", wait=0.2)
        console.send("no ip nat inside source static 192.168.1.10 10.0.12.10", wait=0.2)
        for i in range(1, 5):
            console.send(f"interface GigabitEthernet{i}", wait=0.1)
            console.send("no ip nat inside", wait=0.1)
            console.send("no ip nat outside", wait=0.1)

        # Remove DHCP
        console.send("no ip dhcp pool LAN", wait=0.2)
        console.send("no ip dhcp pool REMOTE", wait=0.2)
        console.send("no ip dhcp excluded-address 192.168.1.1 192.168.1.254", wait=0.1)
        console.send("no ip dhcp excluded-address 192.168.1.1 192.168.1.10", wait=0.1)

        # Remove crypto / VPN
        console.send("no crypto isakmp policy 10", wait=0.2)
        console.send("no crypto isakmp key SecretKey123 address 10.0.12.1", wait=0.1)
        console.send("no crypto isakmp key SecretKey123 address 10.0.12.2", wait=0.1)
        console.send("no crypto isakmp key cisco123 address 10.0.12.1", wait=0.1)
        console.send("no crypto isakmp key cisco123 address 10.0.12.2", wait=0.1)

        # Remove HSRP / VRRP
        for i in range(1, 5):
            console.send(f"interface GigabitEthernet{i}", wait=0.1)
            console.send("no standby 1", wait=0.1)
            console.send("no vrrp 1", wait=0.1)

        # Remove NHRP / tunnel / OSPF auth
        console.send("interface tunnel0", wait=0.1)
        console.send("no ip nhrp authentication", wait=0.1)
        console.send("no ip nhrp network-id", wait=0.1)
        console.send("no ip nhrp nhs", wait=0.1)
        console.send("no ip nhrp redirect", wait=0.1)
        console.send("no ip nhrp shortcut", wait=0.1)
        console.send("no tunnel key", wait=0.1)
        console.send("exit", wait=0.1)

        # Remove OSPF area authentication
        console.send("router ospf 1", wait=0.1)
        console.send("no area 0 authentication", wait=0.1)
        console.send("no area 1 authentication", wait=0.1)
        console.send("no area 1 stub", wait=0.1)
        console.send("no area 1 nssa", wait=0.1)
        console.send("no area 1 virtual-link 2.2.2.2", wait=0.1)
        console.send("no area 1 virtual-link 3.3.3.3", wait=0.1)
        console.send("no area 1 range 10.1.0.0 255.255.0.0", wait=0.1)
        console.send("exit", wait=0.1)

        # Remove EIGRP interface auth
        for i in range(1, 5):
            console.send(f"interface GigabitEthernet{i}", wait=0.1)
            console.send("no ip authentication mode eigrp 100 md5", wait=0.1)
            console.send("no ip authentication key-chain eigrp 100", wait=0.1)
            console.send("no ip ospf message-digest-key 1 md5", wait=0.1)
            console.send("no ip mtu", wait=0.1)

        # Remove NTP / logging / SNMP
        console.send("no ntp server 10.0.12.2", wait=0.1)
        console.send("no ntp server 10.0.12.99", wait=0.1)
        console.send("no ntp authenticate", wait=0.1)
        console.send("no ntp master", wait=0.1)
        console.send("no logging host 10.0.12.2", wait=0.1)
        console.send("no logging host 10.0.12.99", wait=0.1)
        console.send("no snmp-server community public RO", wait=0.1)
        console.send("no snmp-server community pr1vate RO", wait=0.1)

        # Remove key chains
        console.send("no key chain EIGRP_KEY", wait=0.1)
        console.send("no key chain EIGRP_AUTH", wait=0.1)

        # Remove time-ranges
        console.send("no time-range BUSINESS_HOURS", wait=0.1)

        # Remove banners
        console.send("no banner motd", wait=0.1)

        # Remove VTY ACL
        console.send("line vty 0 4", wait=0.1)
        console.send("no access-class 5 in", wait=0.1)
        console.send("transport input ssh telnet", wait=0.1)
        console.send("exit", wait=0.1)

        # Reset hostname, enable DNS, remove users
        console.send("hostname Router", wait=0.2)
        console.send("ip domain-lookup", wait=0.1)

        console.send("end", wait=0.5)

        # No shut all interfaces so links come up for next scenario
        console.send("configure terminal", wait=0.3)
        for i in range(1, 5):
            console.send(f"interface GigabitEthernet{i}", wait=0.1)
            console.send("no shutdown", wait=0.2)
        console.send("end", wait=0.3)
        console.send("terminal length 0", wait=0.2)

        console.close()
        return True
    except Exception:
        return False


class ScenarioEngine:
    """Manages troubleshooting scenario lifecycle with per-user progress tracking."""

    def __init__(self, lab_manager, username=None):
        self.lab = lab_manager
        self.username = username or "default"
        self.state = self._load_state()

    def _load_state(self):
        if os.path.exists(SCENARIO_STATE_PATH):
            try:
                with open(SCENARIO_STATE_PATH) as f:
                    data = json.load(f)
                    if data:
                        # Migrate old format (flat) to new format (per-user)
                        if "users" not in data and "completed" in data:
                            old_completed = data.get("completed", [])
                            data = {
                                "active": data.get("active"),
                                "active_user": None,
                                "users": {
                                    "default": {
                                        "completed": old_completed,
                                        "attempts": {},
                                        "total_time": 0,
                                    }
                                },
                            }
                        return data
            except (json.JSONDecodeError, ValueError):
                pass
        return {"active": None, "active_user": None, "users": {}}

    def _save_state(self):
        with open(SCENARIO_STATE_PATH, "w") as f:
            json.dump(self.state, f, indent=2)

    def _user_data(self, username=None):
        """Get or create user progress data."""
        u = username or self.username
        if u not in self.state.setdefault("users", {}):
            self.state["users"][u] = {
                "completed": [],
                "attempts": {},
                "total_time": 0,
                "started_at": None,
            }
        return self.state["users"][u]

    def get_user_progress(self, username=None):
        """Get progress summary for a user."""
        ud = self._user_data(username)
        return {
            "username": username or self.username,
            "completed": ud.get("completed", []),
            "completed_count": len(ud.get("completed", [])),
            "total": len(SCENARIOS),
            "attempts": ud.get("attempts", {}),
            "total_time": ud.get("total_time", 0),
        }

    def get_all_progress(self):
        """Get progress for all users (admin view)."""
        results = []
        for username, ud in self.state.get("users", {}).items():
            completed = ud.get("completed", [])
            attempts = ud.get("attempts", {})
            total_attempts = sum(a.get("count", 0) for a in attempts.values())
            results.append({
                "username": username,
                "completed_count": len(completed),
                "total": len(SCENARIOS),
                "percent": round(len(completed) / len(SCENARIOS) * 100),
                "total_attempts": total_attempts,
                "total_time_min": round(ud.get("total_time", 0) / 60),
                "completed_ids": completed,
            })
        # Sort by completion count descending
        results.sort(key=lambda x: x["completed_count"], reverse=True)
        return results

    def list_scenarios(self, category=None, difficulty=None):
        """List available scenarios."""
        scenarios = SCENARIOS
        if category:
            scenarios = [s for s in scenarios if category.lower() in s["category"].lower()]
        if difficulty:
            scenarios = [s for s in scenarios if s["difficulty"] == int(difficulty)]

        completed = set(self.state.get("completed", []))

        print(f"\n{'ID':<5} {'Name':<35} {'Category':<18} {'Diff':<6} {'Status'}")
        print("─" * 85)
        for s in scenarios:
            status = "✓ Done" if s["id"] in completed else ""
            diff = "★" * s["difficulty"] + "☆" * (5 - s["difficulty"])
            print(f"{s['id']:<5} {s['name']:<35} {s['category']:<18} {diff:<6} {status}")

        total = len(SCENARIOS)
        done = len(completed)
        print(f"\nProgress: {done}/{total} completed")
        print(f"\nFilter: labctl scenario list [category] [difficulty]")
        print(f"Categories: Interface, Static, OSPF, EIGRP, BGP, ACL, NAT, VPN/GRE, Services, Advanced")

    def get_scenario(self, scenario_id):
        """Get a scenario by ID."""
        for s in SCENARIOS:
            if s["id"] == int(scenario_id):
                return s
        return None

    def deploy(self, scenario_id):
        """Deploy a troubleshooting scenario."""
        scenario = self.get_scenario(scenario_id)
        if not scenario:
            raise ValueError(f"Scenario {scenario_id} not found. Valid: 1-100")

        if self.state.get("active"):
            print(f"  Switching from scenario {self.state['active']}...")
            self.state["active"] = None
            self.state["active_user"] = None
            self._save_state()

        print(f"\n{'='*60}")
        print(f"  SCENARIO {scenario['id']}: {scenario['name']}")
        print(f"  Category: {scenario['category']}")
        print(f"  Difficulty: {'★' * scenario['difficulty']}{'☆' * (5 - scenario['difficulty'])}")
        print(f"{'='*60}")

        print(f"\nDeploying topology...")

        needed = {name: dtype for name, dtype in scenario["devices"]}
        existing = {n["name"]: n for n in self.lab._get_nodes()}

        # Strategy 1: FAST — devices already running with matching names
        running_match = all(
            name in existing and existing[name]["status"] == "started"
            for name in needed
        )

        if running_match:
            print(f"  Fast mode — reusing {len(needed)} running device(s)")

            # Try VM snapshot restore first (instant — ~5 sec)
            restored = self.lab.vm_snapshot_restore("clean")
            if restored:
                print(f"  VM state restored from snapshot (instant)")
                time.sleep(2)
            else:
                # No VM snapshot — config wipe (slower, ~30 sec)
                print(f"  No VM snapshot — wiping configs...")
                for name, _ in scenario["devices"]:
                    if reset_device_config(self.lab, name):
                        print(f"  {name}: config reset")
                    else:
                        print(f"  {name}: reset failed")

            # Clear all links and reconnect
            for link in (self.lab._get_links() or []):
                try:
                    self.lab._api("DELETE", f"/projects/{self.lab.project_id}/links/{link['link_id']}")
                except Exception:
                    pass

            for a, ia, b, ib in scenario.get("links", []):
                try:
                    self.lab.connect(a, ia, b, ib)
                except Exception as e:
                    print(f"  Link error: {e}")

            # Auto-configure immediately
            self.state["active"] = scenario["id"]
            self.state["active_user"] = self.username
            ud = self._user_data()
            ud["started_at"] = time.time()
            sid_str = str(scenario["id"])
            ud.setdefault("attempts", {}).setdefault(sid_str, {"count": 0, "solved": False})
            ud["attempts"][sid_str]["count"] += 1
            self._save_state()
            time.sleep(2)
            self.configure(scenario["id"])
            return

        # Strategy 2: COLD BOOT — need new devices
        print(f"  Cold boot — creating {len(needed)} device(s) (2-3 min)...")

        # Remove all existing
        for node in self.lab._get_nodes():
            try:
                self.lab.remove_device(node["name"])
            except Exception:
                pass

        for name, dtype in scenario["devices"]:
            try:
                self.lab.add_device(name, dtype)
            except Exception as e:
                print(f"  Device error: {e}")

        for a, ia, b, ib in scenario.get("links", []):
            try:
                self.lab.connect(a, ia, b, ib)
            except Exception as e:
                print(f"  Link error: {e}")

        for name, _ in scenario["devices"]:
            try:
                self.lab.start_device(name)
            except Exception:
                pass

        print(f"\n  Devices booting... Configure once all are ready.")

        self.state["active"] = scenario["id"]
        self.state["active_user"] = self.username
        ud = self._user_data()
        ud["started_at"] = time.time()
        sid_str = str(scenario["id"])
        ud.setdefault("attempts", {}).setdefault(sid_str, {"count": 0, "solved": False})
        ud["attempts"][sid_str]["count"] += 1
        self._save_state()

    def configure(self, scenario_id=None):
        """Push base config + break config to devices."""
        sid = scenario_id or self.state.get("active")
        if not sid:
            print("No active scenario. Deploy one first: labctl scenario start <id>")
            return

        scenario = self.get_scenario(sid)
        if not scenario:
            raise ValueError(f"Scenario {sid} not found.")

        print("Pushing base configurations...")

        # Push base configs
        for device_name, commands in scenario["base_config"].items():
            node = self.lab._find_node(device_name)
            if not node:
                print(f"  {device_name}: NOT FOUND — skip")
                continue
            if node["status"] != "started":
                print(f"  {device_name}: not running — skip")
                continue

            port = node.get("console")
            if not port:
                print(f"  {device_name}: no console port — skip")
                continue

            console = DeviceConsole(port=port)
            if console.connect():
                console.send_config(commands)
                console.close()
                print(f"  {device_name}: base config applied ✓")
            else:
                print(f"  {device_name}: could not connect to console (port {port})")

        # Wait a moment for configs to converge
        print("\nWaiting for convergence...")
        time.sleep(10)

        # Push break configs
        print("Introducing faults...")
        for device_name, commands in scenario["break_config"].items():
            node = self.lab._find_node(device_name)
            if not node or node["status"] != "started":
                continue

            port = node.get("console")
            console = DeviceConsole(port=port)
            if console.connect():
                console.send_config(commands)
                console.close()
                print(f"  {device_name}: fault injected ✓")

        print(f"\n{'='*60}")
        print(f"  SCENARIO {scenario['id']}: {scenario['name']}")
        print(f"{'='*60}")
        print(f"\n  {scenario['description']}")
        if scenario.get("hint"):
            print(f"\n  (Type 'labctl scenario hint' if you're stuck)")
        print(f"\n  When you think you've fixed it: labctl scenario check")
        print(f"{'='*60}\n")

    def hint(self):
        """Show hint for active scenario."""
        if not self.state.get("active"):
            print("No active scenario.")
            return
        scenario = self.get_scenario(self.state["active"])
        if scenario and scenario.get("hint"):
            print(f"\n  Hint: {scenario['hint']}\n")
        else:
            print("No hint available for this scenario.")

    def check(self):
        """Validate if the user fixed the issue."""
        if not self.state.get("active"):
            print("No active scenario.")
            return

        scenario = self.get_scenario(self.state["active"])
        if not scenario:
            return

        print(f"Checking scenario {scenario['id']}: {scenario['name']}...")
        all_passed = True

        for device_name, (command, pattern) in scenario.get("validate", {}).items():
            node = self.lab._find_node(device_name)
            if not node or node["status"] != "started":
                print(f"  {device_name}: not running — FAIL")
                all_passed = False
                continue

            port = node.get("console")
            console = DeviceConsole(port=port)
            if console.connect():
                output = console.get_output(command)
                console.close()

                if re.search(pattern, output):
                    print(f"  {device_name}: {command} — PASS ✓")
                else:
                    print(f"  {device_name}: {command} — FAIL ✗")
                    all_passed = False
            else:
                print(f"  {device_name}: cannot connect — FAIL")
                all_passed = False

        if all_passed:
            print(f"\n  ✓ SCENARIO {scenario['id']} SOLVED! Well done!")
            ud = self._user_data()
            sid = scenario["id"]
            if sid not in ud.get("completed", []):
                ud.setdefault("completed", []).append(sid)
            # Track solve time
            started = ud.get("started_at")
            if started:
                elapsed = time.time() - started
                ud["total_time"] = ud.get("total_time", 0) + elapsed
                sid_str = str(sid)
                if sid_str in ud.get("attempts", {}):
                    ud["attempts"][sid_str]["solved"] = True
                    ud["attempts"][sid_str]["solve_time"] = round(elapsed)
                print(f"  Solved in {int(elapsed // 60)}m {int(elapsed % 60)}s")
            self._save_state()
        else:
            print(f"\n  ✗ Not fixed yet. Keep troubleshooting!")
            print(f"  Need help? labctl scenario hint")

    def stop(self):
        """Reset devices to clean state — keeps VMs running for fast next scenario."""
        if not self.state.get("active"):
            print("No active scenario.")
            return

        scenario = self.get_scenario(self.state["active"])
        if scenario:
            print(f"Cleaning up scenario {scenario['id']}...")

            # Try instant VM snapshot restore first
            restored = self.lab.vm_snapshot_restore("clean")
            if restored:
                print(f"  VM state restored (instant)")
            else:
                # Fallback: config wipe
                for name, _ in scenario["devices"]:
                    if reset_device_config(self.lab, name):
                        print(f"  {name}: config wiped")
                    else:
                        print(f"  {name}: not running or unreachable")

            # Remove scenario-specific links
            try:
                for link in (self.lab._get_links() or []):
                    try:
                        self.lab._api("DELETE", f"/projects/{self.lab.project_id}/links/{link['link_id']}")
                    except Exception:
                        pass
            except Exception:
                pass

            print(f"  Devices clean and ready for next scenario.")

        self.state["active"] = None
        self._save_state()
        print("Scenario stopped. Devices removed.")

    def random(self, difficulty=None):
        """Pick a random uncompleted scenario."""
        completed = set(self.state.get("completed", []))
        available = [s for s in SCENARIOS if s["id"] not in completed]
        if difficulty:
            available = [s for s in available if s["difficulty"] == int(difficulty)]

        if not available:
            print("You've completed all scenarios! 🎉" if not difficulty else f"All difficulty {difficulty} scenarios completed!")
            return

        pick = random.choice(available)
        print(f"Random pick: Scenario {pick['id']} — {pick['name']} (Difficulty: {'★' * pick['difficulty']})")
        print(f"Deploy with: labctl scenario start {pick['id']}")
