#!/bin/bash
#
# ELKIE Local LLM Honeypot Setup Script
# For: Dell PowerEdge with Dual Xeon Platinum 8168 (48 cores, 96GB RAM)
#
# This script sets up a high-interaction SSH honeypot using local LLM
# inference via Ollama - no API costs!
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/cowrie-llm"

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║     ELKIE Local LLM Honeypot Setup                            ║"
echo "║     High-Interaction SSH Honeypot with CPU-Based AI           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root for port binding
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Not running as root. You may need sudo for port 22 redirection.${NC}"
fi

# Function to check system resources
check_system() {
    echo -e "${BLUE}[1/6] Checking system resources...${NC}"

    # Check CPU cores
    CORES=$(nproc)
    echo "  CPU Cores: $CORES"
    if [ "$CORES" -lt 8 ]; then
        echo -e "${YELLOW}  Warning: Less than 8 cores detected. LLM inference may be slow.${NC}"
    else
        echo -e "${GREEN}  ✓ Sufficient CPU cores for LLM inference${NC}"
    fi

    # Check RAM
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    echo "  Total RAM: ${TOTAL_RAM}GB"
    if [ "$TOTAL_RAM" -lt 16 ]; then
        echo -e "${YELLOW}  Warning: Less than 16GB RAM. Consider using smaller models.${NC}"
    else
        echo -e "${GREEN}  ✓ Sufficient RAM for LLM models${NC}"
    fi

    # Check Docker
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}  ✓ Docker is installed${NC}"
    else
        echo -e "${RED}  ✗ Docker not found. Please install Docker first.${NC}"
        exit 1
    fi

    # Check Docker Compose
    if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
        echo -e "${GREEN}  ✓ Docker Compose is available${NC}"
    else
        echo -e "${RED}  ✗ Docker Compose not found. Please install it first.${NC}"
        exit 1
    fi
}

# Function to create directories
create_directories() {
    echo -e "${BLUE}[2/6] Creating directories...${NC}"

    mkdir -p "$LOG_DIR"
    mkdir -p "$SCRIPT_DIR/logs"

    echo -e "${GREEN}  ✓ Log directory created: $LOG_DIR${NC}"
}

# Function to select LLM model based on available RAM
select_model() {
    echo -e "${BLUE}[3/6] Selecting optimal LLM model...${NC}"

    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')

    if [ "$TOTAL_RAM" -ge 32 ]; then
        MODEL="mistral:7b-instruct-v0.2-q4_K_M"
        echo "  Selected: Mistral 7B (best quality)"
    elif [ "$TOTAL_RAM" -ge 16 ]; then
        MODEL="neural-chat:7b-v3.3-q4_K_M"
        echo "  Selected: Neural Chat 7B (good balance)"
    else
        MODEL="phi:2.7b-chat-v2-q4_K_M"
        echo "  Selected: Phi 2.7B (fastest)"
    fi

    echo -e "${GREEN}  ✓ Model: $MODEL${NC}"

    # Update config with selected model
    sed -i "s|model:.*|model: \"$MODEL\"|" "$SCRIPT_DIR/config.yml" 2>/dev/null || true
}

# Function to pull Ollama and model
setup_ollama() {
    echo -e "${BLUE}[4/6] Setting up Ollama and downloading model...${NC}"

    # Start just the Ollama container first
    cd "$SCRIPT_DIR"
    docker compose up -d ollama

    echo "  Waiting for Ollama to be ready..."
    sleep 10

    # Pull the selected model
    echo "  Downloading model: $MODEL (this may take a few minutes)..."
    docker exec honeypot-ollama ollama pull "$MODEL"

    echo -e "${GREEN}  ✓ Ollama and model ready${NC}"
}

# Function to start all services
start_services() {
    echo -e "${BLUE}[5/6] Starting all honeypot services...${NC}"

    cd "$SCRIPT_DIR"
    docker compose up -d

    echo "  Waiting for services to initialize..."
    sleep 5

    # Check service status
    if docker compose ps | grep -q "Up"; then
        echo -e "${GREEN}  ✓ All services running${NC}"
    else
        echo -e "${RED}  ✗ Some services failed to start${NC}"
        docker compose logs --tail=20
        exit 1
    fi
}

# Function to setup port redirection
setup_port_redirect() {
    echo -e "${BLUE}[6/6] Setting up port redirection...${NC}"

    echo ""
    echo -e "${YELLOW}To redirect SSH traffic to the honeypot, you have several options:${NC}"
    echo ""
    echo "Option 1: iptables (requires root)"
    echo "  sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 8022"
    echo ""
    echo "Option 2: T-Pot integration"
    echo "  Configure T-Pot to forward Cowrie traffic to port 8022"
    echo ""
    echo "Option 3: Use non-standard port"
    echo "  The honeypot is already listening on port 8022"
    echo "  Attackers scanning will find it"
    echo ""
}

# Function to show status
show_status() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     Setup Complete! Honeypot is running.                      ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Services:"
    echo "  - SSH Honeypot:  localhost:8022"
    echo "  - Ollama API:    localhost:11434"
    echo "  - Redis Cache:   localhost:6379"
    echo ""
    echo "Logs:"
    echo "  - Sessions:      $LOG_DIR/sessions.jsonl"
    echo "  - Commands:      $LOG_DIR/commands.jsonl"
    echo ""
    echo "Test the honeypot:"
    echo "  ssh root@localhost -p 8022"
    echo "  Password: root (or other weak passwords)"
    echo ""
    echo "View logs:"
    echo "  docker compose logs -f cowrie-llm-responder"
    echo ""
    echo "Stop services:"
    echo "  docker compose down"
    echo ""
}

# Function for quick test
test_honeypot() {
    echo -e "${BLUE}Testing LLM response generation...${NC}"

    # Test Ollama API
    RESPONSE=$(curl -s http://localhost:11434/api/generate \
        -d '{"model":"'"$MODEL"'","prompt":"Output only: Linux","stream":false}' \
        | grep -o '"response":"[^"]*"' | head -1)

    if [ -n "$RESPONSE" ]; then
        echo -e "${GREEN}  ✓ LLM responding correctly${NC}"
    else
        echo -e "${YELLOW}  ⚠ LLM may still be loading, wait a moment${NC}"
    fi
}

# Main execution
main() {
    check_system
    create_directories
    select_model
    setup_ollama
    start_services
    test_honeypot
    setup_port_redirect
    show_status
}

# Handle arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  (none)    Full setup"
        echo "  start     Start services only"
        echo "  stop      Stop services"
        echo "  status    Show service status"
        echo "  logs      View live logs"
        echo "  test      Test LLM responses"
        ;;
    start)
        cd "$SCRIPT_DIR"
        docker compose up -d
        echo "Services started"
        ;;
    stop)
        cd "$SCRIPT_DIR"
        docker compose down
        echo "Services stopped"
        ;;
    status)
        cd "$SCRIPT_DIR"
        docker compose ps
        ;;
    logs)
        cd "$SCRIPT_DIR"
        docker compose logs -f
        ;;
    test)
        select_model
        test_honeypot
        ;;
    *)
        main
        ;;
esac
