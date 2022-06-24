#!/bin/bash

source setup.env
source base.setup.env

if ! which envsubst > /dev/null 2>&1
then
  echo "envsubst is needed to run this script"
  if [[ $(uname) == "Darwin" ]]
  then
    echo "you can install it with homebrew (https://brew.sh):"
    echo "brew install gettext"
  else
    if which apt-get > /dev/null 2>&1
    then
      echo "you can install it by running"
      echo "apt-get update && apt-get install gettext-base"
    else
      echo "you can install it by installing the package gettext with your package manager"
    fi
  fi
  exit 1
fi

if [[ "x-$NETBIRD_DOMAIN" == "x-" ]]
then
  echo NETBIRD_DOMAIN is not set, please update your setup.env file
  echo If you are migrating from old versions, you migh need to update your variables prefixes from
  echo WIRETRUSTEE_.. TO NETBIRD_
  exit 1
fi

# local development or tests
if [[ $NETBIRD_DOMAIN == "localhost" || $NETBIRD_DOMAIN == "127.0.0.1" ]]
then
  export NETBIRD_MGMT_API_ENDPOINT=http://$NETBIRD_DOMAIN:$NETBIRD_MGMT_API_PORT
  export NETBIRD_MGMT_GRPC_API_ENDPOINT=http://$NETBIRD_DOMAIN:$NETBIRD_MGMT_GRPC_API_PORT
  unset NETBIRD_MGMT_API_CERT_FILE
  unset NETBIRD_MGMT_API_CERT_KEY_FILE
fi

# if not provided, we generate a turn password
if [[ "x-$TURN_PASSWORD" == "x-" ]]
then
  export TURN_PASSWORD=$(openssl rand -base64 32|sed 's/=//g')
fi

MGMT_VOLUMENAME="${VOLUME_PREFIX}${MGMT_VOLUMESUFFIX}"
SIGNAL_VOLUMENAME="${VOLUME_PREFIX}${SIGNAL_VOLUMESUFFIX}"
LETSENCRYPT_VOLUMENAME="${VOLUME_PREFIX}${LETSENCRYPT_VOLUMESUFFIX}"
# if volume with wiretrustee- prefix already exists, use it, else create new with netbird-
OLD_PREFIX='wiretrustee-'
if docker volume ls | grep -q "${OLD_PREFIX}${MGMT_VOLUMESUFFIX}"; then
    MGMT_VOLUMENAME="${OLD_PREFIX}${MGMT_VOLUMESUFFIX}"
fi
if docker volume ls | grep -q "${OLD_PREFIX}${SIGNAL_VOLUMESUFFIX}"; then
    SIGNAL_VOLUMENAME="${OLD_PREFIX}${SIGNAL_VOLUMESUFFIX}"
fi
if docker volume ls | grep -q "${OLD_PREFIX}${LETSENCRYPT_VOLUMESUFFIX}"; then
    LETSENCRYPT_VOLUMENAME="${OLD_PREFIX}${LETSENCRYPT_VOLUMESUFFIX}"
fi

export MGMT_VOLUMENAME
export SIGNAL_VOLUMENAME
export LETSENCRYPT_VOLUMENAME

envsubst < docker-compose.yml.tmpl > docker-compose.yml
envsubst < management.json.tmpl > management.json
envsubst < turnserver.conf.tmpl > turnserver.conf
