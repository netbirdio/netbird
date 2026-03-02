#!/bin/bash
# Build script for NetBird Wails v3 on Linux
set -e

echo "Installing system dependencies for Wails v3 on Linux..."
sudo apt-get update
sudo apt-get install -y \
  libayatana-appindicator3-dev \
  gcc \
  libgtk-3-dev \
  libwebkit2gtk-4.1-dev \
  libglib2.0-dev \
  libsoup-3.0-dev \
  libx11-dev \
  npm

echo "Installing wails3 CLI..."
go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-alpha.72

echo "Building fancyui..."
cd "$(dirname "$0")/.."
wails3 build

echo "Build complete."
