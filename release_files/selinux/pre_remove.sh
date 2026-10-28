#!/bin/sh
# Unloads the policy module on removal only. rpm passes 0 on erase and 1 on
# upgrade, deb passes "remove" or "upgrade".

case "$1" in
  0 | remove) ;;
  *) exit 0 ;;
esac

if ! command -v semodule >/dev/null 2>&1; then
  exit 0
fi

removed=0
if semodule -l 2>/dev/null | grep -q '^netbird[[:space:]]'; then
  if semodule -r netbird; then
    removed=1
  else
    echo "netbird-selinux: unloading the policy module failed" >&2
  fi
fi

if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v restorecon >/dev/null 2>&1; then
  restorecon -iR /usr/bin/netbird /usr/sbin/netbird /usr/local/bin/netbird \
    /etc/netbird /var/lib/netbird /var/log/netbird /var/log/netbird.out.log \
    /var/log/netbird.err.log /etc/ssh/ssh_config.d/99-netbird.conf \
    /etc/iproute2/rt_tables.d /run/netbird /run/wireguard 2>/dev/null || true
fi

# A daemon started under the removed module keeps its old context until it restarts.
if [ "$removed" = 1 ] && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet netbird; then
  systemctl try-restart netbird || echo "netbird-selinux: restarting netbird failed" >&2
fi
exit 0
