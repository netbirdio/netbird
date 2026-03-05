#!/bin/sh

# Step 1, decide if we should use systemd or init/upstart
use_systemctl="True"
systemd_version=0
if ! command -V systemctl >/dev/null 2>&1; then
  use_systemctl="False"
else
    systemd_version=$(systemctl --version | head -1 | sed 's/systemd //g')
fi

# Ensure required directories exist with proper permissions
ensure_required_directories() {
    # Ensure log directory exists
    if [ ! -d /var/log/netbird ]; then
        printf "\033[32m Creating log directory /var/log/netbird\033[0m\n"
        mkdir -p /var/log/netbird
        chmod 755 /var/log/netbird
    fi
    
    # Ensure runtime directory exists (for daemon socket)
    if [ ! -d /var/run/netbird ]; then
        printf "\033[32m Creating runtime directory /var/run/netbird\033[0m\n"
        mkdir -p /var/run/netbird
        chmod 755 /var/run/netbird
    fi
    
    # Ensure state directory exists
    if [ ! -d /var/lib/netbird ]; then
        printf "\033[32m Creating state directory /var/lib/netbird\033[0m\n"
        mkdir -p /var/lib/netbird
        chmod 755 /var/lib/netbird
    fi
    
    # Ensure cache directory exists
    if [ ! -d /var/cache/netbird ]; then
        printf "\033[32m Creating cache directory /var/cache/netbird\033[0m\n"
        mkdir -p /var/cache/netbird
        chmod 755 /var/cache/netbird
    fi
}

# Install systemd tmpfiles configuration
install_tmpfiles() {
    if [ "${use_systemctl}" = "True" ] && [ -d /usr/lib/tmpfiles.d ]; then
        if [ -f /usr/share/netbird/netbird.tmpfiles ]; then
            cp /usr/share/netbird/netbird.tmpfiles /usr/lib/tmpfiles.d/netbird.conf
            systemd-tmpfiles --create netbird.conf 2> /dev/null || true
        fi
    fi
}

cleanInstall() {
    printf "\033[32m Post Install of an clean install\033[0m\n"
    # Ensure required directories exist before service installation
    ensure_required_directories
    # Install systemd tmpfiles configuration if systemd is available
    install_tmpfiles
    # Step 3 (clean install), enable the service in the proper way for this platform
    /usr/bin/netbird service install
    /usr/bin/netbird service start
}

upgrade() {
    printf "\033[32m Post Install of an upgrade\033[0m\n"
    # Ensure required directories exist before service operations
    ensure_required_directories
    # Install/update systemd tmpfiles configuration if systemd is available
    install_tmpfiles
    
    if [ "${use_systemctl}" = "True" ]; then
      printf "\033[32m Stopping the service\033[0m\n"
      systemctl stop netbird 2> /dev/null || true
    fi
    if [ -e /lib/systemd/system/netbird.service ]; then
      rm -f /lib/systemd/system/netbird.service
      systemctl daemon-reload
    fi
    # will trow an error until everyone upgrade
    /usr/bin/netbird service uninstall 2> /dev/null || true
    /usr/bin/netbird service install
    /usr/bin/netbird service start
}

# Check if this is a clean install or an upgrade
action="$1"
if  [ "$1" = "configure" ] && [ -z "$2" ]; then
  # Alpine linux does not pass args, and deb passes $1=configure
  action="install"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
    # deb passes $1=configure $2=<current version>
    action="upgrade"
fi

case "$action" in
  "1" | "install")
    cleanInstall
    ;;
  "2" | "upgrade")
    upgrade
    ;;
  *)
    cleanInstall
    ;;
esac