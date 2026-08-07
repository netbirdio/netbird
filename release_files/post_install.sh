#!/bin/sh

cleanInstall() {
    printf "\033[32m Post Install of an clean install\033[0m\n"
    # Step 3 (clean install), enable the service in the proper way for this platform
    /usr/bin/netbird service install
    /usr/bin/netbird service start
}

upgrade() {
    printf "\033[32m Post Install of an upgrade\033[0m\n"
    printf "\033[32m Stopping the service\033[0m\n"
    # --keep-tunnel asks the (still-running, pre-upgrade) daemon to leave its
    # kernel WireGuard interface in place instead of tearing it down, so the
    # freshly installed service below can reuse it rather than rebuilding it.
    # Falls back to a plain stop on a daemon that predates this flag.
    /usr/bin/netbird service stop --keep-tunnel 2> /dev/null || /usr/bin/netbird service stop 2> /dev/null || true
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