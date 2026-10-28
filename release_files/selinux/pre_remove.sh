#!/bin/sh
# Unloads the policy module on removal only. rpm passes 0 on erase and 1 on
# upgrade, deb passes "remove" or "upgrade".

case "$1" in
  0 | remove) ;;
  *) exit 0 ;;
esac

if command -v semodule >/dev/null 2>&1; then
  semodule -r netbird 2>/dev/null || true
fi

if command -v restorecon >/dev/null 2>&1; then
  restorecon -R /usr/bin/netbird /usr/sbin/netbird /usr/local/bin/netbird \
    /etc/netbird /var/lib/netbird /var/log/netbird /run/netbird 2>/dev/null || true
fi
exit 0
