#!/usr/bin/env sh

# check if wiretrustee is installed
WT_BIN=$(which wiretrustee)
if [ -n "$WT_BIN" ]
then
  wiretrustee service stop
  wiretrustee service start
fi
# check if netbird is installed
NB_BIN=$(which netbird)
if [ -z "$NB_BIN" ]
then
  echo "netbird is not installed. Please run: brew install netbirdio/tap/netbird"
  exit 1
fi
# start netbird daemon service
netbird service install
netbird service start
netbird version