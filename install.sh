#!/bin/bash

set -e

REPO_URL="https://github.com/ecdhe-x25519/vanguard"
RELEASE_BRANCH="main" 

MODE="release"
CARGO_FLAGS="--release"
BUILD_DIR="."

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --dev)
            MODE="dev"
            CARGO_FLAGS=""
            BUILD_DIR="."
            shift
            ;;
        --release)
            MODE="release"
            CARGO_FLAGS="--release"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--dev] [--release]"
            echo "  --dev      Local build"
            echo "  --release  Release clone"
            exit 0
            ;;
        *)
            echo "Unknown flag: $1"
            exit 1
            ;;
    esac
done

echo "Install mode: [$MODE]"

if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/Cargo not found."
    exit 1
fi

if [ "$MODE" = "release" ]; then
    TMP_DIR=$(mktemp -d -t vanguard-build-XXXXXX)
    BUILD_DIR="$TMP_DIR/vanguard"
    
    echo "Cloning release from GitHub ($REPO_URL)..."
    git clone --depth 1 --single-branch --branch "$RELEASE_BRANCH" "$REPO_URL" "$BUILD_DIR"
    
    cd "$BUILD_DIR"
else
    echo "Building using . ..."

    echo "Building eBPF (vanguard-xdp)..."
    (cd vanguard-xdp && cargo build --release)

    echo "Building userspace (CLI, gRPC, Daemon)..."
    cargo build \
        --workspace \
        --exclude vanguard-xdp \
        --release

    echo "Successfully builded"
fi


if [ "$MODE" = "release" ]; then
    BINARY_PATH="target/release/vanguard-cli"
else
    BINARY_PATH="target/release/vanguard-cli"
fi

INSTALL_PATH="/usr/local/bin/vanguard-cli"

echo "Copying bin to $INSTALL_PATH..."
if [ "$EUID" -ne 0 ]; then
    echo "Need sudo:"
    sudo cp "$BINARY_PATH" "$INSTALL_PATH"
else
    cp "$BINARY_PATH" "$INSTALL_PATH"
fi

sudo chmod +x "$INSTALL_PATH"

if [ "$MODE" = "release" ]; then
    echo "Cleaning temporary files..."
    rm -rf "$TMP_DIR"
fi

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