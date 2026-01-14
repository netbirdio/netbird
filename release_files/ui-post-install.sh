#!/bin/sh

set -e
set -u

# Check if netbird-ui is running
pid="$(pgrep -x -f /usr/bin/netbird-ui || true)"
if [ -n "${pid}" ]
then
  uid="$(cat /proc/"${pid}"/loginuid)"
  # loginuid can be 4294967295 (-1) if not set, fall back to process uid
  if [ "${uid}" = "4294967295" ] || [ "${uid}" = "-1" ]; then
    uid="$(stat -c '%u' /proc/"${pid}")"
  fi
  username="$(id -nu "${uid}")"
  # Only re-run if it was already running
  pkill -x -f /usr/bin/netbird-ui >/dev/null 2>&1
  su - "${username}" -c 'nohup /usr/bin/netbird-ui > /dev/null 2>&1 &'
fi
