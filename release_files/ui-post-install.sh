#!/bin/sh

# Check if netbird-ui is running
if pgrep -x -f /usr/bin/netbird-ui >/dev/null 2>&1;
then
  runner=$(ps --no-headers -o '%U' -p $(pgrep -x -f /usr/bin/netbird-ui) | sed 's/^[ \t]*//;s/[ \t]*$//')
  # Only re-run if it was already running
  pkill -x -f /usr/bin/netbird-ui >/dev/null 2>&1
  su -l - "$runner" -c 'nohup /usr/bin/netbird-ui > /dev/null 2>&1 &'
fi
