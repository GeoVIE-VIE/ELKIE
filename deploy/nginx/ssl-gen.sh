#!/usr/bin/env bash
# ============================================================================
# ELKIE SOC — Generate self-signed SSL certificates for nginx reverse proxy
# ============================================================================
# Usage: ./ssl-gen.sh
# Output: nginx/ssl/elkie.crt, nginx/ssl/elkie.key
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSL_DIR="${SCRIPT_DIR}/ssl"

# Cert details
DAYS=3650
CN="${ELK_IP:-192.168.50.3}"
ORG="ELKIE SOC"
COUNTRY="US"
STATE="Maine"
CITY="Auburn"

mkdir -p "${SSL_DIR}"

echo "[*] Generating self-signed certificate for ${CN} ..."

openssl req -x509 -nodes -newkey rsa:4096 \
    -days "${DAYS}" \
    -keyout "${SSL_DIR}/elkie.key" \
    -out "${SSL_DIR}/elkie.crt" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/CN=${CN}" \
    -addext "subjectAltName=IP:${CN},IP:127.0.0.1,DNS:localhost"

chmod 600 "${SSL_DIR}/elkie.key"
chmod 644 "${SSL_DIR}/elkie.crt"

echo "[+] Certificate generated:"
echo "    Cert: ${SSL_DIR}/elkie.crt"
echo "    Key:  ${SSL_DIR}/elkie.key"
echo "    Valid for ${DAYS} days"
echo ""
openssl x509 -in "${SSL_DIR}/elkie.crt" -noout -subject -dates
