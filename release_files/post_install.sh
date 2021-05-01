#!/bin/sh

# Step 1, decide if we should use systemd or init/upstart
use_systemctl="True"
systemd_version=0
if ! command -V systemctl >/dev/null 2>&1; then
  use_systemctl="False"
else
    systemd_version=$(systemctl --version | head -1 | sed 's/systemd //g')
fi

cleanInstall() {
    printf "\033[32m Post Install of an clean install\033[0m\n"
    # Step 3 (clean install), enable the service in the proper way for this platform
    if [ "${use_systemctl}" = "True" ]; then
        printf "\033[32m Reload the service unit from disk\033[0m\n"
        systemctl daemon-reload ||:
        printf "\033[32m Unmask the service\033[0m\n"
        systemctl unmask wiretrustee ||:
        printf "\033[32m Set the preset flag for the service unit\033[0m\n"
        systemctl preset wiretrustee ||:
        printf "\033[32m Set the enabled flag for the service unit\033[0m\n"
        systemctl enable wiretrustee ||:
        systemctl restart wiretrustee ||:
    fi
}

upgrade() {
    printf "\033[32m Post Install of an upgrade\033[0m\n"
    if [ "${use_systemctl}" = "True" ]; then
        printf "\033[32m Reload the service unit from disk\033[0m\n"
        systemctl daemon-reload ||:
        printf "\033[32m Restarting the service\033[0m\n"
        systemctl restart wiretrustee ||:
    fi
}

# Step 2, check if this is a clean install or an upgrade
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
    printf "\033[32m Post Install of an upgrade\033[0m\n"
    upgrade
    ;;
  *)
    # $1 == version being installed
    printf "\033[32m install\033[0m"
    cleanInstall
    ;;
esac