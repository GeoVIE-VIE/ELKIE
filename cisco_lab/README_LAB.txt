================================================================================
                        CISCO LAB — QUICK REFERENCE
================================================================================

  SSH:  ssh <username>@192.168.30.10
  Pass: (set by admin)

================================================================================
  DEVICE COMMANDS
================================================================================

  labctl add R1 csr              Spin up a CSR1000v router named R1
  labctl add SW1 nxos            Spin up a Nexus 9300v switch named SW1
  labctl remove R1               Destroy a device
  labctl start R1                Boot a device
  labctl stop R1                 Shut down a device
  labctl start-all               Boot everything
  labctl stop-all                Shut down everything

  Device types:
    csr      — Cisco CSR1000v (IOS-XE), 3GB RAM, 4 interfaces
    nxos     — Cisco Nexus 9300v-lite (NX-OS), 6GB RAM, 10 interfaces

================================================================================
  CONNECTING DEVICES
================================================================================

  labctl connect R1 gi0/0 R2 gi0/0       Cable R1's Gi0/0 to R2's Gi0/0
  labctl disconnect R1 gi0/0 R2 gi0/0    Remove a cable

  Interface naming:
    gi0/0, gi1/0, gi2/0 ...              GigabitEthernet (CSR1000v)
    e0/0, e0/1, e1/0 ...                 Ethernet (Nexus)

================================================================================
  CONSOLE ACCESS
================================================================================

  labctl ssh R1                  Console into R1 (telnet)
  labctl R1                      Same thing, shortcut
  labctl console R1              Same thing

  Exit console: Ctrl+] then type 'quit'

================================================================================
  VISIBILITY
================================================================================

  labctl status                  Show all devices, links, console ports
  labctl topology                ASCII topology map
  labctl watch                   Live-updating topology (Ctrl+C to exit)
  labctl images                  Show available/missing images

================================================================================
  TROUBLESHOOTING SCENARIOS (100 total)
================================================================================

  HOW IT WORKS:
    1. Pick a scenario
    2. labctl deploys a broken topology automatically
    3. You SSH into the devices and diagnose the issue
    4. Fix the config
    5. Run 'labctl scenario check' to verify your fix
    6. Move on to the next one

  COMMANDS:
    labctl scenario list                    Browse all 100 scenarios
    labctl scenario list OSPF               Filter by category
    labctl scenario list OSPF 3             Filter by category + difficulty
    labctl scenario start 1                 Deploy scenario #1
    labctl scenario configure               Push configs (run after devices boot)
    labctl scenario hint                    Get a hint if stuck
    labctl scenario check                   Validate your fix
    labctl scenario stop                    Tear down and clean up
    labctl scenario random                  Random scenario
    labctl scenario random 2               Random scenario at difficulty 2

  CATEGORIES:
    Interface        (1-10)    Shut ports, duplex, MTU, IP addressing
    Static           (11-20)   Default routes, next-hop, floating static
    OSPF             (21-30)   Area, timers, auth, passive, network type
    EIGRP            (31-40)   AS, K-values, passive, split-horizon
    BGP              (41-50)   Neighbor, AS, next-hop-self, filtering
    ACL              (51-60)   Deny, direction, implicit deny, protocol 89
    NAT              (61-70)   Inside/outside, ACL, pool, hairpin
    VPN/GRE          (71-80)   Tunnel source, recursive routing, IPsec
    Services         (81-90)   DHCP, NTP, syslog, SSH, SNMP
    Advanced         (91-100)  Redistribution, PBR, HSRP, EtherChannel

  DIFFICULTY:
    ★☆☆☆☆  Beginner       (shut interface, wrong IP)
    ★★☆☆☆  Easy           (duplex, subnet mask, passive-interface)
    ★★★☆☆  Intermediate   (auth mismatch, asymmetric routing, ACL)
    ★★★★☆  Hard           (recursive routing, SIA, policy routing)
    ★★★★★  Expert         (redistribution loops, overlapping NAT, multi-fault)

  TYPICAL WORKFLOW:
    $ labctl scenario start 21
      → Deploys R1 + R2 with OSPF, introduces a fault
    $ labctl scenario configure
      → Pushes configs once devices are booted (~3 min)
    $ labctl ssh R1
      R1# show ip ospf neighbor
      R1# show ip ospf interface
      → (find and fix the issue)
    $ labctl scenario check
      → "SCENARIO 21 SOLVED!"
    $ labctl scenario stop

================================================================================
  RESOURCE MANAGEMENT
================================================================================

  labctl monitor                 Show device uptime and idle time
  labctl monitor timeout 30      Set auto-shutdown to 30 minutes idle
  labctl monitor sweep           Shut down idle devices immediately
  labctl monitor auto            Toggle auto-shutdown on/off

  RAM BUDGET (32GB total):
    CSR1000v:   3GB each    → max ~8 routers
    Nexus 9300: 6GB each    → max ~4 switches
    OS + GNS3:  ~2GB overhead

================================================================================
  ADMIN COMMANDS
================================================================================

  labctl save                    Export running configs to /opt/cisco-lab/configs/
  labctl wipe --confirm          Destroy entire lab (all devices + links)
  labctl adduser jake            Create a user account (run as root)
  labctl users                   List lab users

================================================================================
  ADDING A NEW USER
================================================================================

  As labadmin (or root):
    sudo labctl adduser <username>
    sudo passwd <username>

  Or with SSH keys:
    sudo useradd -m -G labusers -s /bin/bash <username>
    sudo -u <username> mkdir -p /home/<username>/.ssh
    # paste their public key into /home/<username>/.ssh/authorized_keys

  Users can then SSH in and use all labctl commands immediately.

================================================================================
  TIPS
================================================================================

  - CSR1000v takes 3-5 minutes to boot. Be patient after 'labctl start'.
  - Use 'labctl watch' to monitor boot progress in real time.
  - Always 'labctl scenario stop' when done — don't leave devices running.
  - If you get locked out of a device, stop and restart it.
  - 'labctl wipe --confirm' is the nuclear option — destroys everything.
  - Tab completion doesn't work (yet). Type commands exactly.

================================================================================
