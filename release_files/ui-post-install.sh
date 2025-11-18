#!/bin/sh

# Check if netbird-ui is running
pid="$(pgrep -x -f /usr/bin/netbird-ui)"
if [[ "${pid}" ]]
then
  uid="$(cat /proc/"${pid}"/loginuid)"
  username="$(id -nu "${uid}")"
  # Only re-run if it was already running
  pkill -x -f /usr/bin/netbird-ui >/dev/null 2>&1
  su -l - "${username}" -c 'nohup /usr/bin/netbird-ui > /dev/null 2>&1 &'
fi
