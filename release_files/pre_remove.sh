#!/bin/sh
# decide if we should use systemd or init/upstart
use_systemctl="True"
systemd_version=0
if ! command -V systemctl >/dev/null 2>&1; then
  use_systemctl="False"
else
    systemd_version=$(systemctl --version | head -1 | sed 's/systemd //g')
fi

remove() {
  printf "\033[32m Pre uninstall\033[0m\n"

  if [ "${use_systemctl}" = "True" ]; then
    printf "\033[32m Stopping the service\033[0m\n"
    systemctl stop netbird || true

    if [ -e /lib/systemd/system/netbird.service ]; then
      rm -f /lib/systemd/system/netbird.service
      systemctl daemon-reload || true
    fi

  fi
  printf "\033[32m Uninstalling the service\033[0m\n"
  /usr/bin/netbird service uninstall || true


  if [ "${use_systemctl}" = "True" ]; then
     printf "\n\033[32m running daemon reload\033[0m\n"
     systemctl daemon-reload || true
  fi
}

action="$1"

case "$action" in
  "0" | "remove")
    remove
    ;;
  *)
    exit 0
    ;;
esac
