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

# semodule -l prints the module name alone on current SELinux userspace and the name
# followed by a version on older releases.
if ! semodule -l 2>/dev/null | grep -q '^netbird\([[:space:]]\|$\)'; then
  exit 0
fi

# A running daemon would be left without a valid domain when the module goes away
# (unlabeled_t, which systemd cannot signal), so it is stopped first.
active=0
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet netbird; then
  active=1
fi

if [ "$active" = 1 ] && ! systemctl stop netbird; then
  echo "netbird-selinux: stopping netbird failed, leaving the policy module loaded" >&2
  exit 0
fi

if ! semodule -X 200 -r netbird; then
  echo "netbird-selinux: unloading the policy module failed" >&2
fi

if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v restorecon >/dev/null 2>&1; then
  restorecon -iR /usr/bin/netbird /usr/sbin/netbird /usr/local/bin/netbird \
    /etc/netbird /var/lib/netbird /var/log/netbird /var/log/netbird.out.log \
    /var/log/netbird.err.log /etc/ssh/ssh_config.d/99-netbird.conf \
    /etc/iproute2/rt_tables.d/netbird.conf /run/netbird /run/wireguard 2>/dev/null || true
fi
rm -f /run/netbird*.sock

if [ "$active" = 1 ]; then
  systemctl start netbird || echo "netbird-selinux: starting netbird failed" >&2
fi
exit 0
