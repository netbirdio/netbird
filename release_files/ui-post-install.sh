#!/bin/sh

# Check if netbird-ui is running
if pgrep -x -f /usr/bin/netbird-ui >/dev/null 2>&1;
then
  runner=$(ps --no-headers -o '%U' -p $(pgrep -x -f /usr/bin/netbird-ui))
  # Only re-run if it was already running
  pkill -x -f /usr/bin/netbird-ui >/dev/null 2>&1
  runuser -u "$runner" nohup /usr/bin/netbird-ui > /dev/null 2>&1 &
fi
