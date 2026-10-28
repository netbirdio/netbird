#!/bin/sh
# decide if we should use systemd or init/upstart
use_systemctl="True"
systemd_version=0
if ! command -V systemctl >/dev/null 2>&1; then
  use_systemctl="False"
else
    systemd_version=$(systemctl --version | head -1 | sed 's/systemd //g')
fi

# Files the daemon writes outside its own directories. The daemon removes most of
# them on shutdown; this covers a crash mid-write and the routing table name,
# which is left in place while the daemon runs.
remove_host_files() {
  rm -f /etc/ssh/ssh_config.d/99-netbird.conf /etc/ssh/ssh_config.d/99-netbird.conf.tmp
  # Temporary files left by releases that used a random name.
  rm -f /etc/ssh/ssh_config.d/99-netbird.conf.*.tmp
  rm -f /etc/iproute2/rt_tables.d/netbird.conf
  rmdir /etc/iproute2/rt_tables.d 2>/dev/null || true
  # Entry appended to the legacy rt_tables file by older releases.
  if [ -f /etc/iproute2/rt_tables ]; then
    sed -i '/^7120[[:space:]]\{1,\}netbird[[:space:]]*$/d' /etc/iproute2/rt_tables || true
  fi
}

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

  remove_host_files

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
