#!/bin/sh

pkill -x -f /usr/bin/netbird-ui # Kill current running netbird-ui (if exists)
if [[ "$?" = "0" ]] # Only re-run if it was already running
then
  nohup /usr/bin/netbird-ui > /dev/null &disown
fi
