#!/bin/sh
# Loads the netbird policy module and relabels the files it covers. Runs on
# install and upgrade. Without the SELinux tools it does nothing. On a host where
# SELinux is disabled it only stages the module, which takes effect once SELinux is
# enabled and the file system is relabeled.

module=/usr/share/selinux/packages/netbird.pp.bz2

if ! command -v semodule >/dev/null 2>&1 || [ ! -f "$module" ]; then
  exit 0
fi

# Priority 200 is what packaged modules use; 400 is reserved for local changes.
if ! semodule -X 200 -i "$module"; then
  echo "netbird-selinux: loading the policy module failed, netbird keeps running unconfined" >&2
  exit 0
fi

if ! command -v selinuxenabled >/dev/null 2>&1 || ! selinuxenabled; then
  exit 0
fi

# The daemon is stopped while its files are relabeled, so it comes back up in
# the confined domain.
active=0
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet netbird; then
  active=1
fi

if [ "$active" = 1 ] && ! systemctl stop netbird; then
  echo "netbird-selinux: stopping netbird failed, it keeps its old domain until the next restart" >&2
  exit 0
fi

if command -v restorecon >/dev/null 2>&1; then
  restorecon -iR /usr/bin/netbird /usr/sbin/netbird /usr/local/bin/netbird \
    /etc/netbird /var/lib/netbird /var/log/netbird /var/log/netbird.out.log \
    /var/log/netbird.err.log /etc/ssh/ssh_config.d/99-netbird.conf \
    /etc/iproute2/rt_tables.d/netbird.conf /run/netbird /run/wireguard ||
    echo "netbird-selinux: relabeling failed, netbird may start without confinement" >&2
fi

# A socket left by a daemon that ran before the module was loaded carries the generic
# runtime label, and the confined daemon cannot replace it. The daemon recreates it.
rm -f /run/netbird*.sock

if [ "$active" = 1 ]; then
  systemctl start netbird || echo "netbird-selinux: starting netbird failed" >&2
fi
exit 0
