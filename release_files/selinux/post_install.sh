#!/bin/sh
# Loads the netbird policy module and relabels the files it covers. Runs on
# install and upgrade. Without the SELinux tools it does nothing. On a host where
# SELinux is disabled it only stages the module, which takes effect once SELinux is
# enabled and the file system is relabeled.

module=/usr/share/selinux/packages/netbird.pp.bz2

if ! command -v semodule >/dev/null 2>&1 || [ ! -f "$module" ]; then
  exit 0
fi

if ! semodule -i "$module"; then
  echo "netbird-selinux: loading the policy module failed, netbird keeps running unconfined" >&2
  exit 0
fi

if ! command -v selinuxenabled >/dev/null 2>&1 || ! selinuxenabled; then
  exit 0
fi

if command -v restorecon >/dev/null 2>&1; then
  if ! restorecon -iR /usr/bin/netbird /usr/sbin/netbird /usr/local/bin/netbird \
    /etc/netbird /var/lib/netbird /var/log/netbird /var/log/netbird.out.log \
    /var/log/netbird.err.log /etc/ssh/ssh_config.d/99-netbird.conf \
    /etc/iproute2/rt_tables.d /run/netbird /run/wireguard; then
    echo "netbird-selinux: relabeling failed, netbird may start without confinement" >&2
  fi
  restorecon -i /run/netbird*.sock 2>/dev/null || true
fi

# The running daemon keeps its old context until it restarts.
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet netbird; then
  systemctl try-restart netbird || echo "netbird-selinux: restarting netbird failed" >&2
fi
exit 0
