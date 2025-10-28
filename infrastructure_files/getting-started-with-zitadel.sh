#!/bin/bash

set -e

handle_request_command_status() {
  PARSED_RESPONSE=$1
  FUNCTION_NAME=$2
  RESPONSE=$3
  if [[ $PARSED_RESPONSE -ne 0 ]]; then
    echo "ERROR calling $FUNCTION_NAME:" $(echo "$RESPONSE" | jq -r '.message') > /dev/stderr
    exit 1
  fi
}

handle_zitadel_request_response() {
  PARSED_RESPONSE=$1
  FUNCTION_NAME=$2
  RESPONSE=$3
  if [[ $PARSED_RESPONSE == "null" ]]; then
    echo "ERROR calling $FUNCTION_NAME:" $(echo "$RESPONSE" | jq -r '.message') > /dev/stderr
    exit 1
  fi
  sleep 1
}

check_docker_compose() {
  if command -v docker-compose &> /dev/null
  then
      echo "docker-compose"
      return
  fi
  if docker compose --help &> /dev/null
  then
      echo "docker compose"
      return
  fi

  echo "docker-compose is not installed or not in PATH. Please follow the steps from the official guide: https://docs.docker.com/engine/install/" > /dev/stderr
  exit 1
}

check_jq() {
  if ! command -v jq &> /dev/null
  then
    echo "jq is not installed or not in PATH, please install with your package manager. e.g. sudo apt install jq" > /dev/stderr
    exit 1
  fi
}

wait_crdb() {
  set +e
  while true; do
    if $DOCKER_COMPOSE_COMMAND exec -T zdb curl -sf -o /dev/null 'http://localhost:8080/health?ready=1'; then
      break
    fi
    echo -n " ."
    sleep 5
  done
  echo " done"
  set -e
}

init_crdb() {
  if [[ $ZITADEL_DATABASE == "cockroach" ]]; then
    echo -e "\nInitializing Zitadel's CockroachDB\n\n"
    $DOCKER_COMPOSE_COMMAND up -d zdb
    echo ""
    # shellcheck disable=SC2028
    echo -n "Waiting CockroachDB to become ready"
    wait_crdb
    $DOCKER_COMPOSE_COMMAND exec -T zdb /bin/bash -c "cp /cockroach/certs/* /zitadel-certs/ && cockroach cert create-client --overwrite --certs-dir /zitadel-certs/ --ca-key /zitadel-certs/ca.key zitadel_user && chown -R 1000:1000 /zitadel-certs/"
    handle_request_command_status $? "init_crdb failed" ""
  fi
}

get_main_ip_address() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    interface=$(route -n get default | grep 'interface:' | awk '{print $2}')
    ip_address=$(ifconfig "$interface" | grep 'inet ' | awk '{print $2}')
  else
    interface=$(ip route | grep default | awk '{print $5}' | head -n 1)
    ip_address=$(ip addr show "$interface" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
  fi

  echo "$ip_address"
}

wait_pat() {
  PAT_PATH=$1
  set +e
  while true; do
    if [[ -f "$PAT_PATH" ]]; then
      break
    fi
    echo -n " ."
    sleep 1
  done
  echo " done"
  set -e
}

wait_api() {
    INSTANCE_URL=$1
    PAT=$2
    set +e
    counter=1
    while true; do
      FLAGS="-s"
      if [[ $counter -eq 45 ]]; then
        FLAGS="-v"
        echo ""
      fi

      curl $FLAGS --fail --connect-timeout 1 -o /dev/null "$INSTANCE_URL/auth/v1/users/me" -H "Authorization: Bearer $PAT"
      if [[ $? -eq 0 ]]; then
        break
      fi
      if [[ $counter -eq 45 ]]; then
        echo ""
        echo "Unable to connect to Zitadel for more than 45s, please check the output above, your firewall rules and the caddy container logs to confirm if there are any issues provisioning TLS certificates"
      fi
      echo -n " ."
      sleep 1
      counter=$((counter + 1))
    done
    echo " done"
    set -e
}

create_new_project() {
  INSTANCE_URL=$1
  PAT=$2
  PROJECT_NAME="NETBIRD"

  RESPONSE=$(
    curl -sS -X POST "$INSTANCE_URL/management/v1/projects" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{"name": "'"$PROJECT_NAME"'"}'
  )
  PARSED_RESPONSE=$(echo "$RESPONSE" | jq -r '.id')
  handle_zitadel_request_response "$PARSED_RESPONSE" "create_new_project" "$RESPONSE"
  echo "$PARSED_RESPONSE"
}

create_new_application() {
  INSTANCE_URL=$1
  PAT=$2
  APPLICATION_NAME=$3
  BASE_REDIRECT_URL1=$4
  BASE_REDIRECT_URL2=$5
  LOGOUT_URL=$6
  ZITADEL_DEV_MODE=$7
  DEVICE_CODE=$8

  if [[ $DEVICE_CODE == "true" ]]; then
    GRANT_TYPES='["OIDC_GRANT_TYPE_AUTHORIZATION_CODE","OIDC_GRANT_TYPE_DEVICE_CODE","OIDC_GRANT_TYPE_REFRESH_TOKEN"]'
  else
    GRANT_TYPES='["OIDC_GRANT_TYPE_AUTHORIZATION_CODE","OIDC_GRANT_TYPE_REFRESH_TOKEN"]'
  fi

  RESPONSE=$(
    curl -sS -X POST "$INSTANCE_URL/management/v1/projects/$PROJECT_ID/apps/oidc" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{
    "name": "'"$APPLICATION_NAME"'",
    "redirectUris": [
      "'"$BASE_REDIRECT_URL1"'",
      "'"$BASE_REDIRECT_URL2"'"
    ],
    "postLogoutRedirectUris": [
      "'"$LOGOUT_URL"'"
    ],
    "RESPONSETypes": [
      "OIDC_RESPONSE_TYPE_CODE"
    ],
    "grantTypes": '"$GRANT_TYPES"',
    "appType": "OIDC_APP_TYPE_USER_AGENT",
    "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE",
    "version": "OIDC_VERSION_1_0",
    "devMode": '"$ZITADEL_DEV_MODE"',
    "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
    "accessTokenRoleAssertion": true,
    "skipNativeAppSuccessPage": true
  }'
  )

  PARSED_RESPONSE=$(echo "$RESPONSE" | jq -r '.clientId')
  handle_zitadel_request_response "$PARSED_RESPONSE" "create_new_application" "$RESPONSE"
  echo "$PARSED_RESPONSE"
}

create_service_user() {
  INSTANCE_URL=$1
  PAT=$2

  RESPONSE=$(
    curl -sS -X POST "$INSTANCE_URL/management/v1/users/machine" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{
            "userName": "netbird-service-account",
            "name": "Netbird Service Account",
            "description": "Netbird Service Account for IDP management",
            "accessTokenType": "ACCESS_TOKEN_TYPE_JWT"
      }'
  )
  PARSED_RESPONSE=$(echo "$RESPONSE" | jq -r '.userId')
  handle_zitadel_request_response "$PARSED_RESPONSE" "create_service_user" "$RESPONSE"
  echo "$PARSED_RESPONSE"
}

create_service_user_secret() {
  INSTANCE_URL=$1
  PAT=$2
  USER_ID=$3

  RESPONSE=$(
    curl -sS -X PUT "$INSTANCE_URL/management/v1/users/$USER_ID/secret" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{}'
  )
  SERVICE_USER_CLIENT_ID=$(echo "$RESPONSE" | jq -r '.clientId')
  handle_zitadel_request_response "$SERVICE_USER_CLIENT_ID" "create_service_user_secret_id" "$RESPONSE"
  SERVICE_USER_CLIENT_SECRET=$(echo "$RESPONSE" | jq -r '.clientSecret')
  handle_zitadel_request_response "$SERVICE_USER_CLIENT_SECRET" "create_service_user_secret" "$RESPONSE"
}

add_organization_user_manager() {
  INSTANCE_URL=$1
  PAT=$2
  USER_ID=$3

  RESPONSE=$(
    curl -sS -X POST "$INSTANCE_URL/management/v1/orgs/me/members" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{
            "userId": "'"$USER_ID"'",
            "roles": [
              "ORG_USER_MANAGER"
            ]
      }'
  )
  PARSED_RESPONSE=$(echo "$RESPONSE" | jq -r '.details.creationDate')
  handle_zitadel_request_response "$PARSED_RESPONSE" "add_organization_user_manager" "$RESPONSE"
  echo "$PARSED_RESPONSE"
}

create_admin_user() {
    INSTANCE_URL=$1
    PAT=$2
    USERNAME=$3
    PASSWORD=$4
    RESPONSE=$(
        curl -sS -X POST "$INSTANCE_URL/management/v1/users/human/_import" \
          -H "Authorization: Bearer $PAT" \
          -H "Content-Type: application/json" \
          -d '{
                "userName": "'"$USERNAME"'",
                "profile": {
                  "firstName": "Zitadel",
                  "lastName": "Admin"
                },
                "email": {
                  "email": "'"$USERNAME"'",
                  "isEmailVerified": true
                },
                "password": "'"$PASSWORD"'",
                "passwordChangeRequired": true
          }'
      )
      PARSED_RESPONSE=$(echo "$RESPONSE" | jq -r '.userId')
      handle_zitadel_request_response "$PARSED_RESPONSE" "create_admin_user" "$RESPONSE"
      echo "$PARSED_RESPONSE"
}

add_instance_admin() {
  INSTANCE_URL=$1
  PAT=$2
  USER_ID=$3

  RESPONSE=$(
    curl -sS -X POST "$INSTANCE_URL/admin/v1/members" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{
            "userId": "'"$USER_ID"'",
            "roles": [
              "IAM_OWNER"
            ]
      }'
  )
  PARSED_RESPONSE=$(echo "$RESPONSE" | jq -r '.details.creationDate')
  handle_zitadel_request_response "$PARSED_RESPONSE" "add_instance_admin" "$RESPONSE"
  echo "$PARSED_RESPONSE"
}

delete_auto_service_user() {
  INSTANCE_URL=$1
  PAT=$2

  RESPONSE=$(
    curl -sS -X GET "$INSTANCE_URL/auth/v1/users/me" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
  )
  USER_ID=$(echo "$RESPONSE" | jq -r '.user.id')
  handle_zitadel_request_response "$USER_ID" "delete_auto_service_user_get_user" "$RESPONSE"

  RESPONSE=$(
      curl -sS -X DELETE "$INSTANCE_URL/admin/v1/members/$USER_ID" \
        -H "Authorization: Bearer $PAT" \
        -H "Content-Type: application/json" \
  )
  PARSED_RESPONSE=$(echo "$RESPONSE" | jq -r '.details.changeDate')
  handle_zitadel_request_response "$PARSED_RESPONSE" "delete_auto_service_user_remove_instance_permissions" "$RESPONSE"

  RESPONSE=$(
      curl -sS -X DELETE "$INSTANCE_URL/management/v1/orgs/me/members/$USER_ID" \
        -H "Authorization: Bearer $PAT" \
        -H "Content-Type: application/json" \
  )
  PARSED_RESPONSE=$(echo "$RESPONSE" | jq -r '.details.changeDate')
  handle_zitadel_request_response "$PARSED_RESPONSE" "delete_auto_service_user_remove_org_permissions" "$RESPONSE"
  echo "$PARSED_RESPONSE"
}

delete_default_zitadel_admin() {
  INSTANCE_URL=$1
  PAT=$2

  # Search for the default zitadel-admin user
  RESPONSE=$(
    curl -sS -X POST "$INSTANCE_URL/management/v1/users/_search" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{
        "queries": [
          {
            "userNameQuery": {
              "userName": "zitadel-admin@",
              "method": "TEXT_QUERY_METHOD_STARTS_WITH"
            }
          }
        ]
      }'
  )
  
  DEFAULT_ADMIN_ID=$(echo "$RESPONSE" | jq -r '.result[0].id // empty')
  
  if [ -n "$DEFAULT_ADMIN_ID" ] && [ "$DEFAULT_ADMIN_ID" != "null" ]; then
    echo "Found default zitadel-admin user with ID: $DEFAULT_ADMIN_ID"

    RESPONSE=$(
        curl -sS -X DELETE "$INSTANCE_URL/management/v1/users/$DEFAULT_ADMIN_ID" \
          -H "Authorization: Bearer $PAT" \
          -H "Content-Type: application/json" \
    )
    PARSED_RESPONSE=$(echo "$RESPONSE" | jq -r '.details.changeDate // "deleted"')
    handle_zitadel_request_response "$PARSED_RESPONSE" "delete_default_zitadel_admin" "$RESPONSE"

  else
    echo "Default zitadel-admin user not found: $RESPONSE"
  fi
}

init_zitadel() {
  echo -e "\nInitializing Zitadel with NetBird's applications\n"
  INSTANCE_URL="$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"

  TOKEN_PATH=./machinekey/zitadel-admin-sa.token

  echo -n "Waiting for Zitadel's PAT to be created "
  wait_pat "$TOKEN_PATH"
  echo "Reading Zitadel PAT"
  PAT=$(cat $TOKEN_PATH)
  if [ "$PAT" = "null" ]; then
    echo "Failed requesting getting Zitadel PAT"
    exit 1
  fi

  echo -n "Waiting for Zitadel to become ready "
  wait_api "$INSTANCE_URL" "$PAT"

  echo "Deleting default zitadel-admin user..."
  delete_default_zitadel_admin "$INSTANCE_URL" "$PAT"

  #  create the zitadel project
  echo "Creating new zitadel project"
  PROJECT_ID=$(create_new_project "$INSTANCE_URL" "$PAT")

  ZITADEL_DEV_MODE=false
  BASE_REDIRECT_URL=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN
  if [[ $NETBIRD_HTTP_PROTOCOL == "http" ]]; then
    ZITADEL_DEV_MODE=true
  fi

  # create zitadel spa applications
  echo "Creating new Zitadel SPA Dashboard application"
  DASHBOARD_APPLICATION_CLIENT_ID=$(create_new_application "$INSTANCE_URL" "$PAT" "Dashboard" "$BASE_REDIRECT_URL/nb-auth" "$BASE_REDIRECT_URL/nb-silent-auth" "$BASE_REDIRECT_URL/" "$ZITADEL_DEV_MODE" "false")

  echo "Creating new Zitadel SPA Cli application"
  CLI_APPLICATION_CLIENT_ID=$(create_new_application "$INSTANCE_URL" "$PAT" "Cli" "http://localhost:53000/" "http://localhost:54000/" "http://localhost:53000/" "true" "true")

  MACHINE_USER_ID=$(create_service_user "$INSTANCE_URL" "$PAT")

  SERVICE_USER_CLIENT_ID="null"
  SERVICE_USER_CLIENT_SECRET="null"

  create_service_user_secret "$INSTANCE_URL" "$PAT" "$MACHINE_USER_ID"

  DATE=$(add_organization_user_manager "$INSTANCE_URL" "$PAT" "$MACHINE_USER_ID")

  ZITADEL_ADMIN_USERNAME="admin@$NETBIRD_DOMAIN"
  ZITADEL_ADMIN_PASSWORD="$(openssl rand -base64 32 | sed 's/=//g')@"

  HUMAN_USER_ID=$(create_admin_user "$INSTANCE_URL" "$PAT" "$ZITADEL_ADMIN_USERNAME" "$ZITADEL_ADMIN_PASSWORD")

  DATE="null"

  DATE=$(add_instance_admin "$INSTANCE_URL" "$PAT" "$HUMAN_USER_ID")

  DATE="null"
  DATE=$(delete_auto_service_user "$INSTANCE_URL" "$PAT")
  if [ "$DATE" = "null" ]; then
      echo "Failed deleting auto service user"
      echo "Please remove it manually"
  fi

  export NETBIRD_AUTH_CLIENT_ID=$DASHBOARD_APPLICATION_CLIENT_ID
  export NETBIRD_AUTH_CLIENT_ID_CLI=$CLI_APPLICATION_CLIENT_ID
  export NETBIRD_IDP_MGMT_CLIENT_ID=$SERVICE_USER_CLIENT_ID
  export NETBIRD_IDP_MGMT_CLIENT_SECRET=$SERVICE_USER_CLIENT_SECRET
  export ZITADEL_ADMIN_USERNAME
  export ZITADEL_ADMIN_PASSWORD
}

check_nb_domain() {
  DOMAIN=$1
  if [ "$DOMAIN-x" == "-x" ]; then
    echo "The NETBIRD_DOMAIN variable cannot be empty." > /dev/stderr
    return 1
  fi

  if [ "$DOMAIN" == "netbird.example.com" ]; then
    echo "The NETBIRD_DOMAIN cannot be netbird.example.com" > /dev/stderr
    return 1
  fi
  return 0
}

read_nb_domain() {
  READ_NETBIRD_DOMAIN=""
  echo -n "Enter the domain you want to use for NetBird (e.g. netbird.my-domain.com): " > /dev/stderr
  read -r READ_NETBIRD_DOMAIN < /dev/tty
  if ! check_nb_domain "$READ_NETBIRD_DOMAIN"; then
    read_nb_domain
  fi
  echo "$READ_NETBIRD_DOMAIN"
}

get_turn_external_ip() {
  TURN_EXTERNAL_IP_CONFIG="#external-ip="
  IP=$(curl -s -4 https://jsonip.com | jq -r '.ip')
  if [[ "x-$IP" != "x-" ]]; then
    TURN_EXTERNAL_IP_CONFIG="external-ip=$IP"
  fi
  echo "$TURN_EXTERNAL_IP_CONFIG"
}

initEnvironment() {
  CADDY_SECURE_DOMAIN=""
  ZITADEL_EXTERNALSECURE="false"
  ZITADEL_TLS_MODE="disabled"
  ZITADEL_MASTERKEY="$(openssl rand -base64 32 | head -c 32)"
  NETBIRD_PORT=80
  NETBIRD_HTTP_PROTOCOL="http"
  NETBIRD_RELAY_PROTO="rel"
  TURN_USER="self"
  TURN_PASSWORD=$(openssl rand -base64 32 | sed 's/=//g')
  NETBIRD_RELAY_AUTH_SECRET=$(openssl rand -base64 32 | sed 's/=//g')
  TURN_MIN_PORT=49152
  TURN_MAX_PORT=65535
  TURN_EXTERNAL_IP_CONFIG=$(get_turn_external_ip)

  if ! check_nb_domain "$NETBIRD_DOMAIN"; then
    NETBIRD_DOMAIN=$(read_nb_domain)
  fi

  if [ "$NETBIRD_DOMAIN" == "use-ip" ]; then
    NETBIRD_DOMAIN=$(get_main_ip_address)
  else
    ZITADEL_EXTERNALSECURE="true"
    ZITADEL_TLS_MODE="external"
    NETBIRD_PORT=443
    CADDY_SECURE_DOMAIN=", $NETBIRD_DOMAIN:$NETBIRD_PORT"
    NETBIRD_HTTP_PROTOCOL="https"
    NETBIRD_RELAY_PROTO="rels"
  fi

  if [[ "$OSTYPE" == "darwin"* ]]; then
      ZIDATE_TOKEN_EXPIRATION_DATE=$(date -u -v+30M "+%Y-%m-%dT%H:%M:%SZ")
  else
      ZIDATE_TOKEN_EXPIRATION_DATE=$(date -u -d "+30 minutes" "+%Y-%m-%dT%H:%M:%SZ")
  fi

  check_jq

  DOCKER_COMPOSE_COMMAND=$(check_docker_compose)

  if [ -f zitadel.env ]; then
    echo "Generated files already exist, if you want to reinitialize the environment, please remove them first."
    echo "You can use the following commands:"
    echo "  $DOCKER_COMPOSE_COMMAND down --volumes # to remove all containers and volumes"
    echo "  rm -f docker-compose.yml Caddyfile zitadel.env dashboard.env machinekey/zitadel-admin-sa.token turnserver.conf management.json relay.env"
    echo "Be aware that this will remove all data from the database, and you will have to reconfigure the dashboard."
    exit 1
  fi

  if [[ $ZITADEL_DATABASE == "cockroach" ]]; then
        echo "Use CockroachDB as Zitadel database."
        ZDB=$(renderDockerComposeCockroachDB)
        ZITADEL_DB_ENV=$(renderZitadelCockroachDBEnv)
  else
      echo "Use Postgres as default Zitadel database."
      echo "For using CockroachDB please the environment variable 'export ZITADEL_DATABASE=cockroach'."
      POSTGRES_ROOT_PASSWORD="$(openssl rand -base64 32 | sed 's/=//g')@"
      POSTGRES_ZITADEL_PASSWORD="$(openssl rand -base64 32 | sed 's/=//g')@"
      ZDB=$(renderDockerComposePostgres)
      ZITADEL_DB_ENV=$(renderZitadelPostgresEnv)
      renderPostgresEnv > zdb.env
  fi

  echo Rendering initial files...
  renderDockerCompose > docker-compose.yml
  renderCaddyfile > Caddyfile
  renderZitadelEnv > zitadel.env
  echo "" > dashboard.env
  echo "" > turnserver.conf
  echo "" > management.json
  echo "" > relay.env

  mkdir -p machinekey
  chmod 777 machinekey

  init_crdb

  echo -e "\nStarting Zitadel IDP for user management\n\n"
  $DOCKER_COMPOSE_COMMAND up -d caddy zitadel
  init_zitadel

  echo -e "\nRendering NetBird files...\n"
  renderTurnServerConf > turnserver.conf
  renderManagementJson > management.json
  renderDashboardEnv > dashboard.env
  renderRelayEnv > relay.env

  echo -e "\nStarting NetBird services\n"
  $DOCKER_COMPOSE_COMMAND up -d
  echo -e "\nDone!\n"
  echo "You can access the NetBird dashboard at $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  echo "Login with the following credentials:"
  echo "Username: $ZITADEL_ADMIN_USERNAME" | tee .env
  echo "Password: $ZITADEL_ADMIN_PASSWORD" | tee -a .env
}

renderCaddyfile() {
  cat <<EOF
{
  debug
	servers :80,:443 {
    protocols h1 h2c h2 h3
  }
}

(security_headers) {
    header * {
        # enable HSTS
        # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#strict-transport-security-hsts
        # NOTE: Read carefully how this header works before using it.
        # If the HSTS header is misconfigured or if there is a problem with
        # the SSL/TLS certificate being used, legitimate users might be unable
        # to access the website. For example, if the HSTS header is set to a
        # very long duration and the SSL/TLS certificate expires or is revoked,
        # legitimate users might be unable to access the website until
        # the HSTS header duration has expired.
        # The recommended value for the max-age is 2 year (63072000 seconds).
        # But we are using 1 hour (3600 seconds) for testing purposes
        # and ensure that the website is working properly before setting
        # to two years.

        Strict-Transport-Security "max-age=3600; includeSubDomains; preload"

        # disable clients from sniffing the media type
        # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options
        X-Content-Type-Options "nosniff"

        # clickjacking protection
        # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options
        X-Frame-Options "SAMEORIGIN"

        # xss protection
        # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-xss-protection
        X-XSS-Protection "1; mode=block"

        # Remove -Server header, which is an information leak
        # Remove Caddy from Headers
        -Server

        # keep referrer data off of HTTP connections
        # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#referrer-policy
        Referrer-Policy strict-origin-when-cross-origin
    }
}

:80${CADDY_SECURE_DOMAIN} {
    import security_headers
    # relay
    reverse_proxy /relay* relay:80
    # Signal
    reverse_proxy /ws-proxy/signal* signal:80
    reverse_proxy /signalexchange.SignalExchange/* h2c://signal:10000
    # Management
    reverse_proxy /api/* management:80
    reverse_proxy /ws-proxy/management* management:80
    reverse_proxy /management.ManagementService/* h2c://management:80
    # Zitadel
    reverse_proxy /zitadel.admin.v1.AdminService/* h2c://zitadel:8080
    reverse_proxy /admin/v1/* h2c://zitadel:8080
    reverse_proxy /zitadel.auth.v1.AuthService/* h2c://zitadel:8080
    reverse_proxy /auth/v1/* h2c://zitadel:8080
    reverse_proxy /zitadel.management.v1.ManagementService/* h2c://zitadel:8080
    reverse_proxy /management/v1/* h2c://zitadel:8080
    reverse_proxy /zitadel.system.v1.SystemService/* h2c://zitadel:8080
    reverse_proxy /system/v1/* h2c://zitadel:8080
    reverse_proxy /assets/v1/* h2c://zitadel:8080
    reverse_proxy /ui/* h2c://zitadel:8080
    reverse_proxy /oidc/v1/* h2c://zitadel:8080
    reverse_proxy /saml/v2/* h2c://zitadel:8080
    reverse_proxy /oauth/v2/* h2c://zitadel:8080
    reverse_proxy /.well-known/openid-configuration h2c://zitadel:8080
    reverse_proxy /openapi/* h2c://zitadel:8080
    reverse_proxy /debug/* h2c://zitadel:8080
    reverse_proxy /device/* h2c://zitadel:8080
    reverse_proxy /device h2c://zitadel:8080
    reverse_proxy /zitadel.user.v2.UserService/* h2c://zitadel:8080
    # Dashboard
    reverse_proxy /* dashboard:80
}
EOF
}

renderTurnServerConf() {
  cat <<EOF
listening-port=3478
$TURN_EXTERNAL_IP_CONFIG
tls-listening-port=5349
min-port=$TURN_MIN_PORT
max-port=$TURN_MAX_PORT
fingerprint
lt-cred-mech
user=$TURN_USER:$TURN_PASSWORD
realm=wiretrustee.com
cert=/etc/coturn/certs/cert.pem
pkey=/etc/coturn/private/privkey.pem
log-file=stdout
no-software-attribute
pidfile="/var/tmp/turnserver.pid"
no-cli
EOF
}

renderManagementJson() {
  cat <<EOF
{
    "Stuns": [
        {
            "Proto": "udp",
            "URI": "stun:$NETBIRD_DOMAIN:3478"
        }
    ],
    "Relay": {
        "Addresses": ["$NETBIRD_RELAY_PROTO://$NETBIRD_DOMAIN:$NETBIRD_PORT"],
        "CredentialsTTL": "24h",
        "Secret": "$NETBIRD_RELAY_AUTH_SECRET"
    },
    "Signal": {
        "Proto": "$NETBIRD_HTTP_PROTOCOL",
        "URI": "$NETBIRD_DOMAIN:$NETBIRD_PORT"
    },
    "HttpConfig": {
        "AuthIssuer": "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN",
        "AuthAudience": "$NETBIRD_AUTH_CLIENT_ID",
        "OIDCConfigEndpoint":"$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/.well-known/openid-configuration"
    },
    "IdpManagerConfig": {
        "ManagerType": "zitadel",
        "ClientConfig": {
            "Issuer": "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN",
            "TokenEndpoint": "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth/v2/token",
            "ClientID": "$NETBIRD_IDP_MGMT_CLIENT_ID",
            "ClientSecret": "$NETBIRD_IDP_MGMT_CLIENT_SECRET",
            "GrantType": "client_credentials"
        },
        "ExtraConfig": {
            "ManagementEndpoint": "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/management/v1"
        }
    },
  "DeviceAuthorizationFlow": {
      "Provider": "hosted",
      "ProviderConfig": {
          "Audience": "$NETBIRD_AUTH_CLIENT_ID_CLI",
          "ClientID": "$NETBIRD_AUTH_CLIENT_ID_CLI",
          "Scope": "openid"
      }
    },
    "PKCEAuthorizationFlow": {
        "ProviderConfig": {
            "Audience": "$NETBIRD_AUTH_CLIENT_ID_CLI",
            "ClientID": "$NETBIRD_AUTH_CLIENT_ID_CLI",
            "Scope": "openid profile email offline_access",
            "RedirectURLs": ["http://localhost:53000/","http://localhost:54000/"]
        }
    }
}
EOF
}

renderDashboardEnv() {
  cat <<EOF
# Endpoints
NETBIRD_MGMT_API_ENDPOINT=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN
NETBIRD_MGMT_GRPC_API_ENDPOINT=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN
# OIDC
AUTH_AUDIENCE=$NETBIRD_AUTH_CLIENT_ID
AUTH_CLIENT_ID=$NETBIRD_AUTH_CLIENT_ID
AUTH_AUTHORITY=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN
USE_AUTH0=false
AUTH_SUPPORTED_SCOPES="openid profile email offline_access"
AUTH_REDIRECT_URI=/nb-auth
AUTH_SILENT_REDIRECT_URI=/nb-silent-auth
# SSL
NGINX_SSL_PORT=443
# Letsencrypt
LETSENCRYPT_DOMAIN=none
EOF
}

renderZitadelEnv() {
  cat <<EOF
ZITADEL_LOG_LEVEL=debug
ZITADEL_MASTERKEY=$ZITADEL_MASTERKEY
ZITADEL_EXTERNALSECURE=$ZITADEL_EXTERNALSECURE
ZITADEL_TLS_ENABLED="false"
ZITADEL_EXTERNALPORT=$NETBIRD_PORT
ZITADEL_EXTERNALDOMAIN=$NETBIRD_DOMAIN
ZITADEL_FIRSTINSTANCE_PATPATH=/machinekey/zitadel-admin-sa.token
ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_USERNAME=zitadel-admin-sa
ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_NAME=Admin
ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_SCOPES=openid
ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_EXPIRATIONDATE=$ZIDATE_TOKEN_EXPIRATION_DATE
$ZITADEL_DB_ENV
EOF
}

renderZitadelCockroachDBEnv() {
  cat <<EOF
ZITADEL_DATABASE_COCKROACH_HOST=zdb
ZITADEL_DATABASE_COCKROACH_USER_USERNAME=zitadel_user
ZITADEL_DATABASE_COCKROACH_USER_SSL_MODE=verify-full
ZITADEL_DATABASE_COCKROACH_USER_SSL_ROOTCERT="/zdb-certs/ca.crt"
ZITADEL_DATABASE_COCKROACH_USER_SSL_CERT="/zdb-certs/client.zitadel_user.crt"
ZITADEL_DATABASE_COCKROACH_USER_SSL_KEY="/zdb-certs/client.zitadel_user.key"
ZITADEL_DATABASE_COCKROACH_ADMIN_SSL_MODE=verify-full
ZITADEL_DATABASE_COCKROACH_ADMIN_SSL_ROOTCERT="/zdb-certs/ca.crt"
ZITADEL_DATABASE_COCKROACH_ADMIN_SSL_CERT="/zdb-certs/client.root.crt"
ZITADEL_DATABASE_COCKROACH_ADMIN_SSL_KEY="/zdb-certs/client.root.key"
EOF
}

renderZitadelPostgresEnv() {
  cat <<EOF
ZITADEL_DATABASE_POSTGRES_HOST=zdb
ZITADEL_DATABASE_POSTGRES_PORT=5432
ZITADEL_DATABASE_POSTGRES_DATABASE=zitadel
ZITADEL_DATABASE_POSTGRES_USER_USERNAME=zitadel
ZITADEL_DATABASE_POSTGRES_USER_PASSWORD=$POSTGRES_ZITADEL_PASSWORD
ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE=disable
ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME=root
ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD=$POSTGRES_ROOT_PASSWORD
ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE=disable
EOF
}

renderPostgresEnv() {
  cat <<EOF
POSTGRES_USER=root
POSTGRES_PASSWORD=$POSTGRES_ROOT_PASSWORD
EOF
}

renderRelayEnv() {
  cat <<EOF
NB_LOG_LEVEL=info
NB_LISTEN_ADDRESS=:80
NB_EXPOSED_ADDRESS=$NETBIRD_RELAY_PROTO://$NETBIRD_DOMAIN:$NETBIRD_PORT
NB_AUTH_SECRET=$NETBIRD_RELAY_AUTH_SECRET
EOF
}

renderDockerCompose() {
  cat <<EOF
services:
  # Caddy reverse proxy
  caddy:
    image: caddy
    restart: unless-stopped
    networks: [ netbird ]
    ports:
      - '443:443'
      - '443:443/udp'
      - '80:80'
    volumes:
      - netbird_caddy_data:/data
      - ./Caddyfile:/etc/caddy/Caddyfile
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
  # UI dashboard
  dashboard:
    image: netbirdio/dashboard:latest
    restart: unless-stopped
    networks: [netbird]
    env_file:
      - ./dashboard.env
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
  # Signal
  signal:
    image: netbirdio/signal:latest
    restart: unless-stopped
    networks: [netbird]
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
  # Relay
  relay:
    image: netbirdio/relay:latest
    restart: unless-stopped
    networks: [netbird]
    env_file:
      - ./relay.env
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
  # Management
  management:
    image: netbirdio/management:latest
    restart: unless-stopped
    networks: [netbird]
    volumes:
      - netbird_management:/var/lib/netbird
      - ./management.json:/etc/netbird/management.json
    command: [
      "--port", "80",
      "--log-file", "console",
      "--log-level", "info",
      "--disable-anonymous-metrics=false",
      "--single-account-mode-domain=netbird.selfhosted",
      "--dns-domain=netbird.selfhosted",
      "--idp-sign-key-refresh-enabled",
    ]
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
  # Coturn, AKA relay server
  coturn:
    image: coturn/coturn
    restart: unless-stopped
    #domainname: netbird.relay.selfhosted
    volumes:
      - ./turnserver.conf:/etc/turnserver.conf:ro
    network_mode: host
    command:
      - -c /etc/turnserver.conf
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
  # Zitadel - identity provider
  zitadel:
    restart: 'always'
    networks: [netbird]
    image: 'ghcr.io/zitadel/zitadel:v2.64.1'
    command: 'start-from-init --masterkeyFromEnv --tlsMode $ZITADEL_TLS_MODE'
    env_file:
      - ./zitadel.env
    depends_on:
      zdb:
        condition: 'service_healthy'
    volumes:
      - ./machinekey:/machinekey
      - netbird_zitadel_certs:/zdb-certs:ro
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
$ZDB
  netbird_zdb_data:
  netbird_management:
  netbird_caddy_data:
  netbird_zitadel_certs:

networks:
  netbird:
EOF
}

renderDockerComposeCockroachDB() {
  cat <<EOF
  # CockroachDB for Zitadel
  zdb:
    restart: 'always'
    networks: [netbird]
    image: 'cockroachdb/cockroach:latest-v23.2'
    command: 'start-single-node --advertise-addr zdb'
    volumes:
      - netbird_zdb_data:/cockroach/cockroach-data
      - netbird_zdb_certs:/cockroach/certs
      - netbird_zitadel_certs:/zitadel-certs
    healthcheck:
      test: [ "CMD", "curl", "-f", "http://localhost:8080/health?ready=1" ]
      interval: '10s'
      timeout: '30s'
      retries: 5
      start_period: '20s'
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

volumes:
  netbird_zdb_certs:
EOF
}

renderDockerComposePostgres() {
  cat <<EOF
  # Postgres for Zitadel
  zdb:
    restart: 'always'
    networks: [netbird]
    image: 'postgres:16-alpine'
    env_file:
      - ./zdb.env
    volumes:
      - netbird_zdb_data:/var/lib/postgresql/data:rw
    healthcheck:
      test: ["CMD-SHELL", "pg_isready", "-d", "db_prod"]
      interval: 5s
      timeout: 60s
      retries: 10
      start_period: 5s
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
volumes:
EOF
}

initEnvironment
