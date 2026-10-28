#!/bin/sh
# Loads the netbird policy module and relabels the files it covers. Runs on
# install and upgrade, and does nothing on a host without SELinux.

module=/usr/share/selinux/packages/netbird.pp.bz2

if ! command -v semodule >/dev/null 2>&1 || [ ! -f "$module" ]; then
  exit 0
fi

if ! semodule -i "$module"; then
  echo "netbird-selinux: loading the policy module failed, netbird keeps running unconfined" >&2
  exit 0
fi

if command -v restorecon >/dev/null 2>&1; then
  restorecon -R /usr/bin/netbird /usr/sbin/netbird /usr/local/bin/netbird \
    /etc/netbird /var/lib/netbird /var/log/netbird /var/log/netbird.out.log \
    /var/log/netbird.err.log /run/netbird /run/wireguard 2>/dev/null || true
  restorecon /run/netbird*.sock 2>/dev/null || true
fi

# The running daemon keeps its old context until it restarts.
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet netbird; then
  systemctl try-restart netbird || true
fi
exit 0
