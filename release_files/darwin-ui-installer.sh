#!/bin/sh

export PATH=$PATH:/usr/local/bin:/opt/homebrew/bin

# check if wiretrustee is installed
WT_BIN=$(which wiretrustee)
if [ -n "$WT_BIN" ]
then
  echo "Stopping and uninstalling Wiretrustee daemon"
  wiretrustee service stop || true
  wiretrustee service uninstall || true
fi

# check if netbird is installed
NB_BIN=$(which netbird)
if [ -z "$NB_BIN" ]
then
  echo "Netbird daemon is not installed. Please run: brew install netbirdio/tap/netbird"
  exit 1
fi
NB_UI_VERSION=$1
NB_VERSION=$(netbird version)
if [ "X-$NB_UI_VERSION" != "X-$NB_VERSION" ]
then
  echo "Netbird's daemon is running with a different version than the Netbird's UI:"
  echo "Netbird UI Version: $NB_UI_VERSION"
  echo "Netbird Daemon Version: $NB_VERSION"
  echo "Please run: brew install netbirdio/tap/netbird"
  echo "to update it"
fi

if [ -n "$NB_BIN" ]
then
  echo "Stopping NetBird daemon"
  osascript -e 'quit app "Netbird UI"' 2> /dev/null || true
  netbird service stop 2> /dev/null || true
fi

# start netbird daemon service
echo "Starting Netbird daemon"
netbird service install 2> /dev/null || true
netbird service start || true

# start app
open /Applications/Netbird\ UI.app
