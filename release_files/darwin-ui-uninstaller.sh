#!/bin/sh

export PATH=$PATH:/usr/local/bin

# check if netbird is installed
NB_BIN=$(which netbird)
if [ -z "$NB_BIN" ]
then
  exit 0
fi
# start netbird daemon service
echo "netbird daemon service still running. You can uninstall it by running: "
echo "sudo netbird service stop"
echo "sudo netbird service uninstall"
