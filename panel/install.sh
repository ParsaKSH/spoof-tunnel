#!/bin/bash

# Spoof Panel Installer
# Usage: bash <(curl -Ls https://raw.githubusercontent.com/ParsaKSH/spoof-tunnel/main/panel/install.sh)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

REPO="ParsaKSH/spoof-tunnel"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/etc/spoof-panel"
SERVICE_NAME="spoof-panel"

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║         Spoof Panel Installer            ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
echo -e "${GREEN}Detected: ${OS}/${ARCH}${NC}"

# Get latest release
echo -e "${YELLOW}Fetching latest release...${NC}"
LATEST=$(curl -s "https://api.github.com/repos/${REPO}/releases" | grep -o '"tag_name": *"panel-v[^"]*"' | head -1 | grep -o 'panel-v[^"]*')

if [ -z "$LATEST" ]; then
    echo -e "${YELLOW}No panel release found, using latest tag...${NC}"
    LATEST=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep -o '"tag_name": *"[^"]*"' | head -1 | grep -o '"[^"]*"$' | tr -d '"')
fi

if [ -z "$LATEST" ]; then
    echo -e "${RED}Could not find any releases${NC}"
    exit 1
fi

echo -e "${GREEN}Latest version: ${LATEST}${NC}"

# Download panel binary
PANEL_URL="https://github.com/${REPO}/releases/download/${LATEST}/spoof-panel-${OS}-${ARCH}"
echo -e "${YELLOW}Downloading panel...${NC}"
curl -Lo /tmp/spoof-panel "${PANEL_URL}" || {
    echo -e "${RED}Download failed!${NC}"
    exit 1
}
chmod +x /tmp/spoof-panel

# Download spoof binary
SPOOF_URL="https://github.com/${REPO}/releases/download/${LATEST}/spoof-${OS}-${ARCH}"
echo -e "${YELLOW}Downloading spoof tunnel...${NC}"
curl -Lo /tmp/spoof "${SPOOF_URL}" 2>/dev/null || {
    echo -e "${YELLOW}Spoof binary not in this release, will try separate...${NC}"
}

# Install
echo -e "${YELLOW}Installing...${NC}"
mkdir -p "${DATA_DIR}"
mv /tmp/spoof-panel "${INSTALL_DIR}/spoof-panel"

if [ -f /tmp/spoof ]; then
    chmod +x /tmp/spoof
    mv /tmp/spoof "${DATA_DIR}/spoof"
fi

# Stop existing service if running
systemctl stop ${SERVICE_NAME} 2>/dev/null || true

# Generate random credentials
PORT=$(shuf -i 10000-60000 -n 1)
USERNAME=$(head -c 100 /dev/urandom | tr -dc 'a-z0-9' | head -c 8)
PASSWORD=$(head -c 100 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 16)

# Setup the panel (creates DB, user, port)
export SPOOF_DATA_DIR="${DATA_DIR}"

# Create the database and user directly via the binary
${INSTALL_DIR}/spoof-panel -setup-user "${USERNAME}" -setup-pass "${PASSWORD}" -setup-port "${PORT}" 2>/dev/null || {
    # Fallback: use the setup endpoint after starting
    echo -e "${YELLOW}Setting up via API...${NC}"
}

# Create systemd service
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Spoof Panel
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/spoof-panel -port ${PORT}
Environment=SPOOF_DATA_DIR=${DATA_DIR}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl start ${SERVICE_NAME}

# Wait for startup
sleep 2

# Get server IP
SERVER_IP=$(curl -s4 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════╗"
echo "║      Installation Complete! ✓            ║"
echo "╠══════════════════════════════════════════╣"
printf "║  Panel URL:  http://%-20s ║\n" "${SERVER_IP}:${PORT}"
printf "║  Username:   %-27s ║\n" "${USERNAME}"
printf "║  Password:   %-27s ║\n" "${PASSWORD}"
echo "╠══════════════════════════════════════════╣"
echo "║  Service: systemctl status spoof-panel   ║"
echo "║  Logs:    journalctl -u spoof-panel -f   ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "${YELLOW}⚠  Save these credentials! They won't be shown again.${NC}"
echo ""
