#!/bin/sh

set -e
set -u

FRESH_INSTALL_MARKER_DIR="/var/lib/netbird"
FRESH_INSTALL_MARKER="$FRESH_INSTALL_MARKER_DIR/.fresh-install"

# Fresh-vs-upgrade detection. rpm passes $1=1 on install and $1>=2 on
# upgrade; deb passes $1=configure with $2 empty on install and set to the
# previous version on upgrade. Anything unrecognized is treated as an
# upgrade so the breadcrumb is never written spuriously.
action="upgrade"
case "${1:-}" in
  "1")
    action="install"
    ;;
  "configure")
    if [ -z "${2:-}" ]; then
      action="install"
    fi
    ;;
esac

# Only a true fresh install gets the breadcrumb the GUI uses to enable
# launch-on-login by default; the installer itself never writes autostart
# entries. On upgrade any stale breadcrumb is removed (covers a fresh
# install where the GUI never launched before the first update).
if [ "$action" = "install" ]; then
  mkdir -p "$FRESH_INSTALL_MARKER_DIR"
  touch "$FRESH_INSTALL_MARKER"
else
  rm -f "$FRESH_INSTALL_MARKER"
fi

# Check if netbird-ui is running. The pattern also matches an instance
# started with arguments (e.g. a previous --post-update relaunch), which the
# old exact-match -x pattern would miss.
pid="$(pgrep -f '^/usr/bin/netbird-ui( |$)' | head -n 1 || true)"
if [ -n "${pid}" ]
then
  uid="$(cat /proc/"${pid}"/loginuid)"
  # loginuid can be 4294967295 (-1) if not set, fall back to process uid
  if [ "${uid}" = "4294967295" ] || [ "${uid}" = "-1" ]; then
    uid="$(stat -c '%u' /proc/"${pid}")"
  fi
  username="$(id -nu "${uid}")"
  # Only re-run if it was already running. The relaunch carries
  # --post-update so the GUI's first-run autostart default cannot fire.
  pkill -f '^/usr/bin/netbird-ui( |$)' >/dev/null 2>&1 || true
  su - "${username}" -c 'nohup /usr/bin/netbird-ui --post-update > /dev/null 2>&1 &'
fi
