#!/bin/bash

set -e

BUILD_DIR="."

if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/Cargo not found."
    exit 1
fi

echo "Building using . ..."

echo "Building eBPF (vanguard-xdp, vanguard-skb, vanguard-msg)..."
(cd vanguard-xdp && cargo build --release)

echo "Building userspace (CLI, gRPC, Daemon)..."
cargo build \
    --workspace \
    --exclude vanguard-xdp \
    --release

echo "Successfully builded"

BINARY_PATH="target/release/vanguard-cli"
INSTALL_PATH="/usr/local/bin/vanguard-cli"

echo "Copying bin to $INSTALL_PATH..."
if [ "$EUID" -ne 0 ]; then
    echo "Need sudo for: cp "$BINARY_PATH" "$INSTALL_PATH""
    sudo cp "$BINARY_PATH" "$INSTALL_PATH"
else
    cp "$BINARY_PATH" "$INSTALL_PATH"
fi

sudo chmod +x "$INSTALL_PATH"

echo "Cleaning temporary files..."
rm -rf "$TMP_DIR"

echo "Configuring systemd service..."
DAEMON_PATH="$(pwd)/target/release/vanguard-daemon"
SERVICE_FILE="/etc/systemd/system/vanguard.service"

sudo bash -c "cat << EOF > $SERVICE_FILE
[Unit]
Description=XDP-based firewall
After=network.target

[Service]
Type=notify
ExecStart=$DAEMON_PATH
Restart=always
RestartSec=5
User=root
TimeoutStartSec=30

[Install]
WantedBy=multi-user.target
EOF"

echo "Registering service in systemd..."

sudo systemctl daemon-reload
    
sudo systemctl enable vanguard.service

echo "Starting vanguard service..."
sudo systemctl restart vanguard.service

echo "Service status:"
sudo systemctl status vanguard.service --no-pager

echo "Vanguard installed successfully!"