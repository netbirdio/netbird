#!/bin/bash
# NetBird installer for SteamOS (Steam Deck)
#
# Installs NetBird as a user-level service running entirely from /home.
# Uses userspace WireGuard with a real kernel TUN interface for proper
# network performance (important for game streaming via Moonlight/Sunshine).
# Requires sudo once at install (and per update) to grant file capabilities.
# Survives all SteamOS updates without intervention.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/netbirdio/netbird/main/release_files/install-steamos.sh | bash
#   bash install-steamos.sh --update
#   bash install-steamos.sh --uninstall
#
# Environment variables:
#   NETBIRD_RELEASE   - Version to install (default: "latest")
#   GITHUB_TOKEN      - GitHub token for rate-limited API calls
#   NB_MANAGEMENT_URL - Custom management server URL
#   NB_ADMIN_URL      - Custom admin dashboard URL
#   NB_SETUP_KEY      - Setup key for automatic authentication

set -euo pipefail

OWNER="netbirdio"
REPO="netbird"
BINARY="netbird"

INSTALL_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/netbird"
STATE_DIR="${HOME}/.local/share/netbird"
SYSTEMD_DIR="${HOME}/.config/systemd/user"
SERVICE_NAME="netbird"

NETBIRD_RELEASE="${NETBIRD_RELEASE:-latest}"
TAG_NAME=""

# --- Logging ---

info() { printf '\033[1;32m[netbird]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[netbird]\033[0m %s\n' "$*" >&2; }
error() { printf '\033[1;31m[netbird]\033[0m %s\n' "$*" >&2; exit 1; }

# --- Validation ---

check_steamos() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect OS: /etc/os-release not found"
    fi

    . /etc/os-release

    # Accept steamos, or allow --force for other immutable Linux distros
    if [[ "${ID:-}" != "steamos" ]] && [[ "${FORCE:-}" != "true" ]]; then
        warn "This script is designed for SteamOS (detected: ${ID:-unknown})"
        warn "Set FORCE=true to install anyway on immutable Linux distros"
        exit 1
    fi

    info "Detected ${PRETTY_NAME:-SteamOS}"
}

check_arch() {
    case "$(uname -m)" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            error "Unsupported architecture: $(uname -m)"
        ;;
    esac
}

check_dependencies() {
    local missing=""
    for cmd in curl tar systemctl sudo sha256sum; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing="$missing $cmd"
        fi
    done

    if [[ -n "$missing" ]]; then
        error "Missing required commands:$missing"
    fi

    # Verify user-level systemd is functional
    if ! systemctl --user status >/dev/null 2>&1; then
        error "systemctl --user is not functional. Is systemd user session running?"
    fi
}

# --- Release fetching (adapted from install.sh) ---

get_release() {
    local release="$1"
    if [[ "$release" == "latest" ]]; then
        local url="https://pkgs.netbird.io/releases/latest"
    else
        local url="https://api.github.com/repos/${OWNER}/${REPO}/releases/tags/${release}"
    fi

    local output=""
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        output=$(curl -fsSL -H "Authorization: token ${GITHUB_TOKEN}" "$url")
    else
        output=$(curl -fsSL "$url")
    fi

    TAG_NAME=$(echo "$output" | grep -Eo '"tag_name":\s*"v([0-9]+\.){2}[0-9]+"' | tail -n 1)
    echo "$TAG_NAME" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+'
}

download_binary() {
    local dest_dir="${1:-$INSTALL_DIR}"
    local version
    version=$(get_release "$NETBIRD_RELEASE")

    if [[ -z "$version" ]]; then
        error "Failed to determine NetBird version"
    fi

    local version_num="${version#v}"
    local tarball="${BINARY}_${version_num}_linux_${ARCH}.tar.gz"
    local checksums="${BINARY}_${version_num}_checksums.txt"
    local base_url="https://github.com/${OWNER}/${REPO}/releases/download/${version}"

    info "Downloading NetBird ${version} for ${ARCH}..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap "rm -rf '$tmp_dir'" EXIT

    local auth_header=""
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        auth_header="Authorization: token ${GITHUB_TOKEN}"
    fi

    # Download tarball and checksums
    curl -fsSL ${auth_header:+-H "$auth_header"} -o "${tmp_dir}/${tarball}" "${base_url}/${tarball}"
    curl -fsSL ${auth_header:+-H "$auth_header"} -o "${tmp_dir}/${checksums}" "${base_url}/${checksums}"

    # Verify checksum
    info "Verifying checksum..."
    local expected
    expected=$(grep "  ${tarball}$" "${tmp_dir}/${checksums}" | awk '{print $1}')
    if [[ -z "$expected" ]]; then
        error "Checksum for ${tarball} not found in ${checksums}"
    fi

    local actual
    actual=$(sha256sum "${tmp_dir}/${tarball}" | awk '{print $1}')
    if [[ "$expected" != "$actual" ]]; then
        error "Checksum mismatch for ${tarball}: expected ${expected}, got ${actual}"
    fi
    info "Checksum verified"

    tar -xzf "${tmp_dir}/${tarball}" -C "$tmp_dir" "$BINARY"

    mkdir -p "$dest_dir"
    mv "${tmp_dir}/${BINARY}" "${dest_dir}/${BINARY}"
    chmod 755 "${dest_dir}/${BINARY}"

    info "Installed ${dest_dir}/${BINARY} (${version})"
}

# --- Network capabilities ---

apply_capabilities() {
    local binary_path="${1:-${INSTALL_DIR}/${BINARY}}"

    info "Granting network capabilities (sudo required)..."
    if ! sudo setcap cap_net_admin,cap_net_raw+eip "$binary_path"; then
        error "Failed to set capabilities. Is sudo available?"
    fi
    info "Capabilities set on ${binary_path}"
}

verify_capabilities() {
    local binary_path="${1:-${INSTALL_DIR}/${BINARY}}"

    if ! command -v getcap >/dev/null 2>&1; then
        warn "getcap not found, skipping capability verification"
        return 0
    fi

    local caps
    caps=$(getcap "$binary_path" 2>/dev/null || true)
    if [[ "$caps" == *"cap_net_admin"* ]] && [[ "$caps" == *"cap_net_raw"* ]]; then
        info "Verified: ${caps}"
        return 0
    else
        warn "Capabilities not set correctly: ${caps}"
        return 1
    fi
}

# --- Systemd user service ---

write_service_unit() {
    mkdir -p "$SYSTEMD_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$STATE_DIR"

    cat > "${SYSTEMD_DIR}/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=NetBird Client (SteamOS)
Documentation=https://netbird.io/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=NB_CONFIG=${CONFIG_DIR}/config.json
Environment=NB_STATE_DIR=${STATE_DIR}
Environment=NB_DAEMON_ADDR=unix://${STATE_DIR}/netbird.sock
Environment=NB_LOG_FILE=${STATE_DIR}/client.log
ExecStart=${INSTALL_DIR}/${BINARY} service run
Restart=on-failure
RestartSec=5
TimeoutStopSec=10

[Install]
WantedBy=default.target
EOF

    info "Created systemd user service"
}

enable_service() {
    systemctl --user daemon-reload
    systemctl --user enable "${SERVICE_NAME}.service"
    systemctl --user start "${SERVICE_NAME}.service"

    # Enable lingering so the service runs even when not logged into a desktop session
    if command -v loginctl >/dev/null 2>&1; then
        loginctl enable-linger "$(whoami)" 2>/dev/null || \
            warn "Could not enable linger. Service will only run while logged in."
    fi

    info "Service enabled and started"
}

# --- Shell environment ---

configure_shell_env() {
    local shell_rc="${HOME}/.bashrc"
    if [[ -f "${HOME}/.zshrc" ]]; then
        shell_rc="${HOME}/.zshrc"
    fi

    local daemon_addr="unix://${STATE_DIR}/netbird.sock"

    if ! grep -qF "# Added by NetBird installer" "$shell_rc" 2>/dev/null; then
        cat >> "$shell_rc" <<SHELLRC

# Added by NetBird installer
export PATH="${INSTALL_DIR}:\$PATH"
export NB_DAEMON_ADDR="${daemon_addr}"
export NB_CONFIG="${CONFIG_DIR}/config.json"
SHELLRC
        info "Added NetBird environment to ${shell_rc}"
    fi

    # Also export for the current script so auto-connect works
    export PATH="${INSTALL_DIR}:${PATH}"
    export NB_DAEMON_ADDR="${daemon_addr}"
    export NB_CONFIG="${CONFIG_DIR}/config.json"
}

# --- Install ---

do_install() {
    check_steamos
    check_arch
    check_dependencies

    # Check for existing installation
    if [[ -x "${INSTALL_DIR}/${BINARY}" ]]; then
        warn "NetBird is already installed at ${INSTALL_DIR}/${BINARY}"
        warn "Use --update to update or --uninstall to remove first"
        exit 1
    fi

    download_binary
    apply_capabilities
    verify_capabilities
    write_service_unit
    enable_service
    configure_shell_env

    info ""
    info "NetBird installed successfully!"
    info ""
    info "The daemon is running. To connect:"
    info ""

    if [[ -n "${NB_SETUP_KEY:-}" ]]; then
        info "  Connecting with provided setup key..."
        "${INSTALL_DIR}/${BINARY}" up --setup-key "$NB_SETUP_KEY" \
            ${NB_MANAGEMENT_URL:+--management-url "$NB_MANAGEMENT_URL"} \
            ${NB_ADMIN_URL:+--admin-url "$NB_ADMIN_URL"} || \
            warn "Auto-connect failed. Run 'netbird up --setup-key <KEY>' manually."
    else
        info "  With a setup key (recommended for Steam Deck):"
        info "    netbird up --setup-key <YOUR-SETUP-KEY>"
        info ""
        info "  With SSO (device flow):"
        info "    netbird up"
        info "    Then open the printed URL on your phone or PC."
    fi

    info ""
    info "Check status:  netbird status"
    info "View logs:     journalctl --user -u ${SERVICE_NAME} -f"
}

# --- Update ---

do_update() {
    if [[ ! -x "${INSTALL_DIR}/${BINARY}" ]]; then
        error "NetBird is not installed. Run without --update to install."
    fi

    local installed_version
    installed_version=$("${INSTALL_DIR}/${BINARY}" version 2>/dev/null || echo "unknown")

    local latest_version
    latest_version=$(get_release "latest")
    latest_version="${latest_version#v}"

    if [[ "$installed_version" == "$latest_version" ]]; then
        info "Already on latest version (${installed_version})"
        exit 0
    fi

    info "Updating ${installed_version} -> ${latest_version}"

    check_arch
    check_dependencies

    # Download and verify new binary to a staging directory before touching the running service
    local staging_dir
    staging_dir=$(mktemp -d)
    trap "rm -rf '$staging_dir'" RETURN

    download_binary "$staging_dir"

    # Apply capabilities to the new binary before swapping
    apply_capabilities "${staging_dir}/${BINARY}"

    # Regenerate the unit file in case paths or env vars changed
    write_service_unit

    # Only stop the service after the new binary is ready
    systemctl --user stop "${SERVICE_NAME}.service" 2>/dev/null || true

    # Atomic swap: move staged binary into place
    mv "${staging_dir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    chmod 755 "${INSTALL_DIR}/${BINARY}"

    systemctl --user daemon-reload
    systemctl --user start "${SERVICE_NAME}.service"

    info "Updated to ${latest_version}"
}

# --- Uninstall ---

do_uninstall() {
    info "Uninstalling NetBird..."

    # Stop and disable service
    systemctl --user stop "${SERVICE_NAME}.service" 2>/dev/null || true
    systemctl --user disable "${SERVICE_NAME}.service" 2>/dev/null || true

    # Remove files
    rm -f "${SYSTEMD_DIR}/${SERVICE_NAME}.service"
    rm -f "${INSTALL_DIR}/${BINARY}"

    systemctl --user daemon-reload

    info "Removed binary and service"

    # Ask about config/state
    if [[ -d "$CONFIG_DIR" ]] || [[ -d "$STATE_DIR" ]]; then
        info ""
        info "Config and state directories still exist:"
        [[ -d "$CONFIG_DIR" ]] && info "  ${CONFIG_DIR}"
        [[ -d "$STATE_DIR" ]] && info "  ${STATE_DIR}"
        info ""
        info "To remove them (this deletes auth tokens and config):"
        info "  rm -rf ${CONFIG_DIR} ${STATE_DIR}"
    fi

    info "NetBird uninstalled"
}

# --- Main ---

main() {
    local action="${1:-}"
    case "$action" in
        --update)
            do_update
        ;;
        --uninstall)
            do_uninstall
        ;;
        --help|-h)
            cat <<USAGE
NetBird installer for SteamOS (Steam Deck)

Usage:
  install-steamos.sh              Install NetBird
  install-steamos.sh --update     Update to latest version
  install-steamos.sh --uninstall  Remove NetBird

Environment variables:
  NETBIRD_RELEASE     Version to install (default: latest)
  GITHUB_TOKEN        GitHub token for API rate limits
  NB_SETUP_KEY        Setup key for automatic authentication
  NB_MANAGEMENT_URL   Custom management server URL
  NB_ADMIN_URL        Custom admin dashboard URL
  FORCE               Set to "true" to install on non-SteamOS systems

Files:
  ${INSTALL_DIR}/${BINARY}                    Binary
  ${CONFIG_DIR}/config.json            Config
  ${STATE_DIR}/                        State, socket, logs
  ${SYSTEMD_DIR}/${SERVICE_NAME}.service  Systemd unit
USAGE
        ;;
        "")
            do_install
        ;;
        *)
            error "Unknown option: $action (use --help for usage)"
        ;;
    esac
}

main "$@"
