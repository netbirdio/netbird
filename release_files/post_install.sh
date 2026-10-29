#!/bin/sh

# Step 1, decide if we should use systemd or init/upstart
use_systemctl="True"
systemd_version=0
if ! command -V systemctl >/dev/null 2>&1; then
  use_systemctl="False"
else
    systemd_version=$(systemctl --version | head -1 | sed 's/systemd //g')
fi

# The service environment file may hold the PKCS#11 token PIN (NB_TPM_PIN). Package
# upgrades keep a locally modified copy with its old mode, so restrict it on every run.
restrict_env_file() {
    if [ -f /etc/sysconfig/netbird ]; then
      chmod 0600 /etc/sysconfig/netbird
    fi
    return 0
}

# The service install step creates the state and log directories as the installing
# process, so relabel them to what the SELinux policy, when loaded, assigns.
# The routing table name drop-in lives in a directory that stock iproute2 may not ship.
# The package creates it so the confined daemon only has to create its own file in it.
ensure_rt_tables_dir() {
    mkdir -p /etc/iproute2/rt_tables.d
}

restore_selinux_contexts() {
    command -v selinuxenabled >/dev/null 2>&1 || return 0
    selinuxenabled || return 0
    command -v restorecon >/dev/null 2>&1 || return 0
    if ! restorecon -iR /var/lib/netbird /var/log/netbird /etc/netbird; then
      printf "\033[33m Could not restore SELinux contexts on the netbird directories\033[0m\n"
    fi
    return 0
}

cleanInstall() {
    printf "\033[32m Post Install of a clean install\033[0m\n"
    restrict_env_file
    ensure_rt_tables_dir
    # Step 3 (clean install), enable the service in the proper way for this platform
    /usr/bin/netbird service install
    restore_selinux_contexts
    /usr/bin/netbird service start
}

upgrade() {
    printf "\033[32m Post Install of an upgrade\033[0m\n"
    restrict_env_file
    ensure_rt_tables_dir
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
    restore_selinux_contexts
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