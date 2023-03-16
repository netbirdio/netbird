#!/bin/bash

if ! which curl > /dev/null 2>&1
then
    echo "This script uses curl fetch OpenID configuration from IDP."
    echo "Please install curl and re-run the script https://curl.se/"
    echo ""
    exit 1
fi

if ! which jq > /dev/null 2>&1
then
    echo "This script uses jq to load OpenID configuration from IDP."
    echo "Please install jq and re-run the script https://stedolan.github.io/jq/"
    echo ""
    exit 1
fi

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

# Check if letsencrypt was disabled
if [[ "$NETBIRD_DISABLE_LETSENCRYPT" == "true" ]]
then
  export NETBIRD_DASHBOARD_ENDPOINT="https://$NETBIRD_DOMAIN:443"

  echo "Letsencrypt was disabled, the Https-endpoints cannot be used anymore"
  echo " and a reverse-proxy with Https needs to be placed in front of netbird!"
  echo "The following forwards have to be setup:"
  echo "- $NETBIRD_DASHBOARD_ENDPOINT -> dashboard"
  echo "- $NETBIRD_MGMT_API_ENDPOINT -> management"
  echo "You most likely also have to change NETBIRD_MGMT_API_ENDPOINT in base.setup.env and port-mappings in docker-compose.yml.tmpl and rerun this script."
  echo " The target of the forwards depends on your setup."
  echo "You are also free to remove any occurences of the Letsencrypt-volume $LETSENCRYPT_VOLUMENAME"
  echo ""

  export NETBIRD_LETSENCRYPT_DOMAIN="none"
  unset NETBIRD_MGMT_API_CERT_FILE
  unset NETBIRD_MGMT_API_CERT_KEY_FILE
else
  # Kinda ugly, but the dashboard expects the domain or 'none'
  export NETBIRD_LETSENCRYPT_DOMAIN="$NETBIRD_DOMAIN"
fi

# local development or tests
if [[ $NETBIRD_DOMAIN == "localhost" || $NETBIRD_DOMAIN == "127.0.0.1" ]]
then
  export NETBIRD_MGMT_SINGLE_ACCOUNT_MODE_DOMAIN="netbird.selfhosted"
  export NETBIRD_MGMT_API_ENDPOINT=http://$NETBIRD_DOMAIN:$NETBIRD_MGMT_API_PORT
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

#backwards compatibility after migrating to generic OIDC with Auth0
if [[ -z "${NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT}" ]]; then

    if [[ -z "${NETBIRD_AUTH0_DOMAIN}" ]]; then
       # not a backward compatible state
       echo "NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT property must be set in the setup.env file"
       exit 1
    fi

    echo "It seems like you provided an old setup.env file."
    echo "Since the release of v0.8.10, we introduced a new set of properties."
    echo "The script is backward compatible and will continue automatically."
    echo "In the future versions it will be deprecated. Please refer to the documentation to learn about the changes http://netbird.io/docs/getting-started/self-hosting"

    export NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT="https://${NETBIRD_AUTH0_DOMAIN}/.well-known/openid-configuration"
    export NETBIRD_USE_AUTH0="true"
    export NETBIRD_AUTH_AUDIENCE=${NETBIRD_AUTH0_AUDIENCE}
    export NETBIRD_AUTH_CLIENT_ID=${NETBIRD_AUTH0_CLIENT_ID}
fi

echo "loading OpenID configuration from ${NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT} to the openid-configuration.json file"
curl "${NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT}" -q -o openid-configuration.json

export NETBIRD_AUTH_AUTHORITY=$( jq -r  '.issuer' openid-configuration.json )
export NETBIRD_AUTH_JWT_CERTS=$( jq -r  '.jwks_uri' openid-configuration.json )
export NETBIRD_AUTH_SUPPORTED_SCOPES=$( jq -r '.scopes_supported | join(" ")' openid-configuration.json )
export NETBIRD_AUTH_TOKEN_ENDPOINT=$( jq -r  '.token_endpoint' openid-configuration.json )
export NETBIRD_AUTH_DEVICE_AUTH_ENDPOINT=$( jq -r  '.device_authorization_endpoint' openid-configuration.json )

if [ $NETBIRD_USE_AUTH0 == "true" ]
then
    export NETBIRD_AUTH_SUPPORTED_SCOPES="openid profile email offline_access api email_verified"
else
    export NETBIRD_AUTH_SUPPORTED_SCOPES="openid profile email offline_access api"
fi

if [[ ! -z "${NETBIRD_AUTH_DEVICE_AUTH_CLIENT_ID}" ]]; then
    # user enabled Device Authorization Grant feature
    export NETBIRD_AUTH_DEVICE_AUTH_PROVIDER="hosted"
fi

env | grep NETBIRD

envsubst < docker-compose.yml.tmpl > docker-compose.yml
envsubst < management.json.tmpl > management.json
envsubst < turnserver.conf.tmpl > turnserver.conf
