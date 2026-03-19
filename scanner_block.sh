#!/bin/bash
# =============================================================================
# scanner_block.sh — Block known intelligence scanners (Shodan, Censys, etc.)
#
# Installs iptables rules on the T-Pot honeypot to block scanners that
# fingerprint and publicly classify the host as a honeypot.
#
# Usage: Run on T-Pot via SSH, or deploy as a cron job.
#   bash scanner_block.sh [--check|--remove]
# =============================================================================

set -euo pipefail

CHAIN="SCANNER_BLOCK"

# ---- Known scanner CIDR ranges ----
# Sources: MISP warninglists, IPFire wiki, community gists, vendor docs

SHODAN_RANGES=(
    # Shodan core infrastructure (AS47541, AS62567)
    "66.240.192.0/18"
    "71.6.128.0/17"
    "82.221.105.0/24"
    "85.25.43.0/24"
    "85.25.103.0/24"
    "93.120.27.0/24"
    "98.143.148.0/24"
    "104.131.0.0/16"
    "155.94.222.0/24"
    "155.94.254.0/24"
    "185.163.109.0/24"
    "185.181.102.0/24"
    "188.138.9.0/24"
    "198.20.64.0/18"
    "198.20.87.0/24"
    "198.20.99.0/24"
    "208.180.20.0/24"
    "209.126.110.0/24"
    "216.117.2.0/24"
)

CENSYS_RANGES=(
    # Censys official (AS398324) — from MISP warninglist
    "162.142.125.0/24"
    "167.248.133.0/24"
    "167.94.138.0/24"
    "167.94.145.0/24"
    "167.94.146.0/24"
    "199.45.154.0/24"
    "199.45.155.0/24"
    "206.168.34.0/24"
    "66.132.159.0/24"
    "192.35.168.0/23"
    "74.120.14.0/24"
)

BINARYEDGE_RANGES=(
    # BinaryEdge (AS211680)
    "37.19.221.0/24"
    "45.83.64.0/22"
)

RAPID7_RANGES=(
    # Rapid7 Labs / Project Sonar (AS397434)
    "5.63.151.0/24"
    "71.6.233.0/24"
    "88.202.190.0/24"
    "146.185.25.0/24"
)

STRETCHOID_RANGES=(
    # Stretchoid / Onyphe / internet-measurement.com
    "80.82.77.0/24"
    "89.248.167.0/24"
    "89.248.172.0/24"
    "93.174.95.0/24"
    "94.102.49.0/24"
    "185.165.190.0/24"
    "185.165.191.0/24"
)

SHADOWSERVER_RANGES=(
    # Shadowserver Foundation (AS64271)
    "64.62.197.0/24"
    "74.82.47.0/24"
    "184.105.139.0/24"
    "184.105.247.0/24"
    "216.218.206.0/24"
)

CRIMINALIP_RANGES=(
    # CriminalIP / internet scanners
    "43.163.0.0/16"
    "101.43.0.0/16"
)

ZOOMEYE_RANGES=(
    # ZoomEye / Knownsec (Chinese scanner)
    "106.75.0.0/16"
    "122.224.0.0/16"
)

# Combine all ranges
ALL_RANGES=(
    "${SHODAN_RANGES[@]}"
    "${CENSYS_RANGES[@]}"
    "${BINARYEDGE_RANGES[@]}"
    "${RAPID7_RANGES[@]}"
    "${STRETCHOID_RANGES[@]}"
    "${SHADOWSERVER_RANGES[@]}"
    "${CRIMINALIP_RANGES[@]}"
    "${ZOOMEYE_RANGES[@]}"
)

# ---- Functions ----

install_rules() {
    echo "[*] Installing scanner block rules..."

    # Create chain if it doesn't exist
    iptables -N "$CHAIN" 2>/dev/null || true
    # Flush existing rules in the chain
    iptables -F "$CHAIN"

    local count=0
    for cidr in "${ALL_RANGES[@]}"; do
        iptables -A "$CHAIN" -s "$cidr" -j DROP
        ((count++))
    done

    # Insert jump to our chain at the top of INPUT if not already there
    if ! iptables -C INPUT -j "$CHAIN" 2>/dev/null; then
        iptables -I INPUT 1 -j "$CHAIN"
    fi

    # Also block in FORWARD for docker containers
    if ! iptables -C FORWARD -j "$CHAIN" 2>/dev/null; then
        iptables -I FORWARD 1 -j "$CHAIN"
    fi

    # Block on DOCKER-USER chain if it exists (T-Pot uses Docker)
    if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
        if ! iptables -C DOCKER-USER -j "$CHAIN" 2>/dev/null; then
            iptables -I DOCKER-USER 1 -j "$CHAIN"
        fi
    fi

    echo "[+] Installed $count block rules across ${#ALL_RANGES[@]} CIDR ranges"
    echo "[+] Chains: INPUT, FORWARD, DOCKER-USER"
}

check_rules() {
    echo "[*] Current scanner block rules:"
    if iptables -L "$CHAIN" -n 2>/dev/null; then
        echo ""
        echo "Rule count: $(iptables -L "$CHAIN" -n | grep -c DROP)"
        echo ""
        echo "Jump references:"
        for chain in INPUT FORWARD DOCKER-USER; do
            if iptables -C "$chain" -j "$CHAIN" 2>/dev/null; then
                echo "  $chain -> $CHAIN [OK]"
            else
                echo "  $chain -> $CHAIN [MISSING]"
            fi
        done
    else
        echo "  Chain $CHAIN does not exist. Run without --check to install."
    fi
}

remove_rules() {
    echo "[*] Removing scanner block rules..."
    # Remove jumps
    for chain in INPUT FORWARD DOCKER-USER; do
        iptables -D "$chain" -j "$CHAIN" 2>/dev/null || true
    done
    # Flush and delete chain
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    echo "[+] All scanner block rules removed"
}

# ---- Main ----

case "${1:-install}" in
    --check)  check_rules ;;
    --remove) remove_rules ;;
    *)        install_rules ;;
esac
