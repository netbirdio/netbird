#!/bin/sh

export PATH=$PATH:/usr/local/bin:/opt/homebrew/bin

NB_BIN=$(command -v netbird)
if [ -n "$NB_BIN" ]; then
  echo "Stopping NetBird daemon"
  "$NB_BIN" service stop 2>/dev/null || true
  echo "Uninstalling NetBird daemon"
  "$NB_BIN" service uninstall 2>/dev/null || true
fi

PLIST=/Library/LaunchDaemons/netbird.plist
if [ -f "$PLIST" ]; then
  launchctl bootout system "$PLIST" 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
fi

exit 0
