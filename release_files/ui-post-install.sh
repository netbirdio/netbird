#!/bin/sh

set -e
set -u

# Check if netbird-ui is running
pid="$(pgrep -x -f /usr/bin/netbird-ui || true)"
if [ -n "${pid}" ]
then
  username="$(ps -o 'user:256=' -p "${pid}")"
  # Only re-run if it was already running
  pkill -x -f /usr/bin/netbird-ui >/dev/null 2>&1
  # shellcheck disable=SC2086 # Use word-splitting to trim whitespace
  su - ${username} -c 'nohup /usr/bin/netbird-ui > /dev/null 2>&1 &'
fi
