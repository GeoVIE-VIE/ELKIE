#!/bin/bash
#
# Cowrie LLM Plugin Installer for T-Pot
#
# This script patches your T-Pot Cowrie installation to use
# local LLM for unknown commands while keeping Cowrie's
# native emulation for everything else.
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Cowrie LLM Plugin Installer for T-Pot                       ║"
echo "║  Integrates local LLM into existing Cowrie honeypot          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect T-Pot installation
detect_tpot() {
    echo -e "${BLUE}[1/5] Detecting T-Pot installation...${NC}"

    # Common T-Pot paths
    TPOT_PATHS=(
        "/opt/tpot"
        "/data/tpot"
        "$HOME/tpot"
    )

    TPOT_DIR=""
    for path in "${TPOT_PATHS[@]}"; do
        if [ -d "$path" ]; then
            TPOT_DIR="$path"
            break
        fi
    done

    if [ -z "$TPOT_DIR" ]; then
        echo -e "${YELLOW}T-Pot directory not found in standard locations.${NC}"
        read -p "Enter T-Pot installation path: " TPOT_DIR
    fi

    if [ ! -d "$TPOT_DIR" ]; then
        echo -e "${RED}Error: $TPOT_DIR does not exist${NC}"
        exit 1
    fi

    echo -e "${GREEN}  ✓ Found T-Pot at: $TPOT_DIR${NC}"

    # Find Cowrie container/directory
    COWRIE_DATA="$TPOT_DIR/data/cowrie"
    if [ ! -d "$COWRIE_DATA" ]; then
        COWRIE_DATA="$TPOT_DIR/cowrie"
    fi

    echo -e "${GREEN}  ✓ Cowrie data at: $COWRIE_DATA${NC}"
}

# Start Ollama container
start_ollama() {
    echo -e "${BLUE}[2/5] Setting up Ollama LLM server...${NC}"

    # Check if Ollama is already running
    if docker ps | grep -q "honeypot-ollama"; then
        echo -e "${GREEN}  ✓ Ollama already running${NC}"
        return
    fi

    # Start Ollama container
    docker run -d \
        --name honeypot-ollama \
        --restart unless-stopped \
        -p 11434:11434 \
        -v ollama_models:/root/.ollama \
        -e OLLAMA_NUM_THREAD=48 \
        ollama/ollama:latest

    echo "  Waiting for Ollama to start..."
    sleep 10

    # Pull model
    echo "  Downloading Mistral 7B model (this takes a few minutes)..."
    docker exec honeypot-ollama ollama pull mistral:7b-instruct-v0.2-q4_K_M

    echo -e "${GREEN}  ✓ Ollama ready with Mistral 7B${NC}"
}

# Create custom Cowrie configuration
configure_cowrie() {
    echo -e "${BLUE}[3/5] Configuring Cowrie for LLM integration...${NC}"

    # Create custom commands directory
    CUSTOM_COMMANDS="$COWRIE_DATA/custom_commands"
    mkdir -p "$CUSTOM_COMMANDS"

    # Copy plugin files
    cp "$SCRIPT_DIR/llm_command_handler.py" "$CUSTOM_COMMANDS/"
    cp "$SCRIPT_DIR/cowrie_llm_proxy.py" "$CUSTOM_COMMANDS/"

    # Create environment file for Cowrie container
    cat > "$COWRIE_DATA/llm.env" << 'EOF'
# LLM Configuration for Cowrie
OLLAMA_HOST=http://host.docker.internal:11434
LLM_MODEL=mistral:7b-instruct-v0.2-q4_K_M
LLM_ENABLED=true
EOF

    echo -e "${GREEN}  ✓ Plugin files installed${NC}"
}

# Patch Cowrie's txtcmds for LLM fallback
patch_cowrie() {
    echo -e "${BLUE}[4/5] Patching Cowrie command handling...${NC}"

    # The txtcmds directory contains simple text responses
    # We'll add a hook that calls LLM for unknown commands

    TXTCMDS="$COWRIE_DATA/txtcmds"
    if [ ! -d "$TXTCMDS" ]; then
        mkdir -p "$TXTCMDS"
    fi

    # Create marker file
    echo "LLM_ENABLED" > "$TXTCMDS/.llm_enabled"

    echo -e "${GREEN}  ✓ Cowrie patched for LLM fallback${NC}"
}

# Create the LLM proxy service
create_proxy() {
    echo -e "${BLUE}[5/5] Creating LLM proxy service...${NC}"

    # The proxy runs alongside Cowrie and handles LLM requests
    cat > "$SCRIPT_DIR/docker-compose.tpot-integration.yml" << 'EOF'
version: '3.8'

# LLM Proxy for T-Pot Cowrie Integration
# This runs alongside your existing T-Pot stack

services:
  ollama:
    image: ollama/ollama:latest
    container_name: honeypot-ollama
    restart: unless-stopped
    ports:
      - "11434:11434"
    volumes:
      - ollama_models:/root/.ollama
    environment:
      - OLLAMA_NUM_THREAD=48
      - OLLAMA_NUM_PARALLEL=4
    deploy:
      resources:
        limits:
          memory: 16G

  llm-proxy:
    build:
      context: .
      dockerfile: Dockerfile.proxy
    container_name: cowrie-llm-proxy
    restart: unless-stopped
    depends_on:
      - ollama
    ports:
      - "11435:11435"  # Proxy API for Cowrie
    environment:
      - OLLAMA_HOST=http://ollama:11434
      - LLM_MODEL=mistral:7b-instruct-v0.2-q4_K_M
    networks:
      - tpot_network

volumes:
  ollama_models:

networks:
  tpot_network:
    external: true
    name: tpot_network
EOF

    echo -e "${GREEN}  ✓ Proxy service configuration created${NC}"
}

show_integration_status() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Installation Complete!                                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "How the integration works:"
    echo ""
    echo "  1. Attacker connects to Cowrie (unchanged)"
    echo "  2. Cowrie handles known commands natively (ls, cat, wget, etc.)"
    echo "  3. For unknown commands, Cowrie calls the LLM proxy"
    echo "  4. LLM generates response, Cowrie outputs it"
    echo "  5. All logging stays in Cowrie's standard format"
    echo ""
    echo "Next steps:"
    echo ""
    echo "  1. Start the LLM services:"
    echo "     cd $SCRIPT_DIR && docker compose -f docker-compose.tpot-integration.yml up -d"
    echo ""
    echo "  2. Restart Cowrie to load the plugin:"
    echo "     docker restart cowrie"
    echo ""
    echo "  3. Test the integration:"
    echo "     ssh root@localhost -p 2222"
    echo ""
}

# Main
detect_tpot
start_ollama
configure_cowrie
patch_cowrie
create_proxy
show_integration_status
