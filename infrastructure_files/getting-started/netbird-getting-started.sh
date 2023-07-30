#!/bin/bash

set -e

handle_request_command_status() {
  COMMAND_EXEC_STATUS=$1
  FUNCTION_NAME=$2
  RESPONSE=$3
  if [[ $COMMAND_EXEC_STATUS -ne 0 ]]; then
    echo "ERROR calling $FUNCTION_NAME: $(echo $RESPONSE | jq -r '.message')"
    exit 1
  fi
}

create_new_project() {
  INSTANCE_URL=$1
  PAT=$2
  PROJECT_NAME="NETBIRD"

  RESPONSE=$(
    curl -X POST --fail-with-body "$INSTANCE_URL/management/v1/projects" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{"name": "'"$PROJECT_NAME"'"}'
  )
  handle_request_command_status $? "create_new_project" "$RESPONSE"
  echo "$RESPONSE" | jq -r '.id'
}

create_new_application() {
  INSTANCE_URL=$1
  PAT=$2
  APPLICATION_NAME="netbird"

  RESPONSE=$(
    curl -X POST --fail-with-body "$INSTANCE_URL/management/v1/projects/$PROJECT_ID/apps/oidc" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{
    "name": "'"$APPLICATION_NAME"'",
    "redirectUris": [
      "'"$BASE_REDIRECT_URL"'/auth"
    ],
    "RESPONSETypes": [
      "OIDC_RESPONSE_TYPE_CODE"
    ],
    "grantTypes": [
      "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
      "OIDC_GRANT_TYPE_REFRESH_TOKEN"
    ],
    "appType": "OIDC_APP_TYPE_USER_AGENT",
    "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE",
    "postLogoutRedirectUris": [
      "'"$BASE_REDIRECT_URL"'/silent-auth"
    ],
    "version": "OIDC_VERSION_1_0",
    "devMode": '"$ZITADEL_DEV_MODE"',
    "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
    "accessTokenRoleAssertion": true,
    "skipNativeAppSuccessPage": true
  }'
  )
  handle_request_command_status $? "create_new_application" "$RESPONSE"
  echo "$RESPONSE" | jq -r '.clientId'
}

create_service_user() {
  INSTANCE_URL=$1
  PAT=$2

  RESPONSE=$(
    curl -X POST --fail-with-body "$INSTANCE_URL/management/v1/users/machine" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{
            "userName": "netbird-service-account",
            "name": "Netbird Service Account",
            "description": "Netbird Service Account for IDP management",
            "accessTokenType": "ACCESS_TOKEN_TYPE_JWT"
      }'
  )
  handle_request_command_status $? "create_service_user" "$RESPONSE"
  echo "$RESPONSE" | jq -r '.userId'
}

create_service_user_secret() {
  INSTANCE_URL=$1
  PAT=$2
  USER_ID=$3

  RESPONSE=$(
    curl -X PUT --fail-with-body "$INSTANCE_URL/management/v1/users/$USER_ID/secret" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{}'
  )
  handle_request_command_status $? "create_service_user_secret" "$RESPONSE"
  SERVICE_USER_CLIENT_ID=$(echo "$RESPONSE" | jq -r '.clientId')
  SERVICE_USER_CLIENT_SECRET=$(echo "$RESPONSE" | jq -r '.clientSecret')
}

add_organization_user_manager() {
  INSTANCE_URL=$1
  PAT=$2
  USER_ID=$3

  RESPONSE=$(
    curl -X POST --fail-with-body "$INSTANCE_URL/management/v1/orgs/me/members" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{
            "userId": "'$USER_ID'",
            "roles": [
              "ORG_USER_MANAGER"
            ]
      }'
  )
  handle_request_command_status $? "add_organization_user_manager" "$RESPONSE"
  echo "$RESPONSE" | jq -r '.details.creationDate'
}

create_admin_user() {
    INSTANCE_URL=$1
    PAT=$2
    USERNAME=$3
    PASSWORD=$4
    RESPONSE=$(
        curl -X POST --fail-with-body "$INSTANCE_URL/management/v1/users/human/_import" \
          -H "Authorization: Bearer $PAT" \
          -H "Content-Type: application/json" \
          -d '{
                "userName": "'$USERNAME'",
                "profile": {
                  "firstName": "Zitadel",
                  "lastName": "Admin"
                },
                "email": {
                  "email": "'$USERNAME'",
                  "isEmailVerified": true
                },
                "password": "'$PASSWORD'",
                "passwordChangeRequired": true
          }'
      )
      handle_request_command_status $? "create_admin_user" "$RESPONSE"
      echo "$RESPONSE" | jq -r '.userId'
}

add_instance_admin() {
  INSTANCE_URL=$1
  PAT=$2
  USER_ID=$3

  RESPONSE=$(
    curl -X POST --fail-with-body "$INSTANCE_URL/admin/v1/members" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{
            "userId": "'$USER_ID'",
            "roles": [
              "IAM_OWNER"
            ]
      }'
  )
  handle_request_command_status $? "add_instance_admin" "$RESPONSE"
  echo "$RESPONSE" | jq -r '.details.creationDate'
}

delete_auto_service_user() {
  INSTANCE_URL=$1
  PAT=$2

  RESPONSE=$(
    curl -X GET --fail-with-body "$INSTANCE_URL/auth/v1/users/me" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
  )
  handle_request_command_status $? "delete_auto_service_user_get_user" "$RESPONSE"
  USER_ID=$(echo "$RESPONSE" | jq -r '.user.id')

  RESPONSE=$(
      curl -X DELETE --fail-with-body "$INSTANCE_URL/admin/v1/members/$USER_ID" \
        -H "Authorization: Bearer $PAT" \
        -H "Content-Type: application/json" \
  )
  handle_request_command_status $? "delete_auto_service_user_remove_instance_permissions" "$RESPONSE"
  echo "$RESPONSE" | jq -r '.details.changeDate'

  RESPONSE=$(
      curl -X DELETE --fail-with-body "$INSTANCE_URL/management/v1/orgs/me/members/$USER_ID" \
        -H "Authorization: Bearer $PAT" \
        -H "Content-Type: application/json" \
  )
  handle_request_command_status $? "delete_auto_service_user_remove_org_permissions" "$RESPONSE"
  echo "$RESPONSE" | jq -r '.details.changeDate'
}

configure_zitadel_instance() {

  #INSTANCE_URL=$(echo "$NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT" | sed 's/\/\.well-known\/openid-configuration//')

  echo "reading Zitadel PAT"
  PAT=$(cat /Users/maycon/zitadel/machinekey/zitadel-admin-sa.token)
  if [ "$PAT" = "null" ]; then
    echo "failed requesting getting Zitadel PAT"
    exit 1
  fi

  #  create the zitadel project
  echo "creating new zitadel project"
  PROJECT_ID=$(create_new_project "$INSTANCE_URL" "$PAT")
  if [ "$PROJECT_ID" = "null" ]; then
    echo "failed creating new zitadel project"
    exit 1
  fi

  ZITADEL_DEV_MODE=false
  if [[ $NETBIRD_DOMAIN == *"localhost"* ]]; then
    BASE_REDIRECT_URL="http://$NETBIRD_DOMAIN"
    ZITADEL_DEV_MODE=true
  else
    BASE_REDIRECT_URL="https://$NETBIRD_DOMAIN"
  fi

  # create zitadel spa application
  echo "creating new zitadel spa application"
  APPLICATION_CLIENT_ID=$(create_new_application "$INSTANCE_URL" "$PAT")
  if [ "$APPLICATION_CLIENT_ID" = "null" ]; then
    echo "failed creating new zitadel spa application"
    exit 1
  fi

  MACHINE_USER_ID=$(create_service_user "$INSTANCE_URL" "$PAT")
  if [ "$MACHINE_USER_ID" = "null" ]; then
    echo "failed creating new zitadel service user"
    exit 1
  fi

  SERVICE_USER_CLIENT_ID="null"
  SERVICE_USER_CLIENT_SECRET="null"

  create_service_user_secret "$INSTANCE_URL" "$PAT" "$MACHINE_USER_ID"
  if [ "$SERVICE_USER_CLIENT_ID" = "null" ] || [ "$SERVICE_USER_CLIENT_SECRET" = "null" ]; then
    echo "failed creating new zitadel service user secret"
    exit 1
  fi

  DATE=$(add_organization_user_manager "$INSTANCE_URL" "$PAT" "$MACHINE_USER_ID")
  if [ "$DATE" = "null" ]; then
    echo "failed adding service user to organization"
    exit 1
  fi

  ZITADEL_ADMIN_USERNAME="admin@$NETBIRD_DOMAIN"
  ZITADEL_ADMIN_PASSWORD="$(openssl rand -base64 32 | sed 's/=//g')@"

  HUMAN_USER_ID=$(create_admin_user "$INSTANCE_URL" "$PAT" "$ZITADEL_ADMIN_USERNAME" "$ZITADEL_ADMIN_PASSWORD")
  if [ "$HUMAN_USER_ID" = "null" ]; then
    echo "failed creating new zitadel admin user"
    exit 1
  fi

  DATE="null"

  DATE=$(add_instance_admin "$INSTANCE_URL" "$PAT" "$HUMAN_USER_ID")
  if [ "$DATE" = "null" ]; then
      echo "failed adding service user to organization"
      exit 1
  fi

  DATE="null"
  DATE=$(delete_auto_service_user "$INSTANCE_URL" "$PAT")
  if [ "$DATE" = "null" ]; then
      echo "failed deleting auto service user"
      echo "please remove it manually"
  fi

  echo "ZITADEL_PROJECT_ID=$PROJECT_ID" >> .env
  echo "ZITADEL_CLIENT_ID=$APPLICATION_CLIENT_ID" >> .env
  echo "ZITADEL_MACHINE_USER_ID=$MACHINE_USER_ID" >> .env
  echo "ZITADEL_MACHINE_USER_CLIENT_ID=$SERVICE_USER_CLIENT_ID" >> .env
  echo "ZITADEL_MACHINE_USER_CLIENT_SECRET=$SERVICE_USER_CLIENT_SECRET" >> .env
  echo "ZITADEL_ADMIN_USERNAME=$ZITADEL_ADMIN_USERNAME" >> .env
  echo "ZITADEL_ADMIN_PASSWORD=$ZITADEL_ADMIN_PASSWORD" >> .env
  echo "ZITADEL_DEV_MODE=$ZITADEL_DEV_MODE" >> .env

}

configure_zitadel_instance

renderCaddyfile() {
  cat <<EOF
{
    debug
	servers :80,:8080,:443 {
    		protocols h1 h2c
    }
}

:80, :8080 {
    # Signal
    reverse_proxy /signalexchange.SignalExchange/* h2c://signal:10000
    # Management
    reverse_proxy /api/* management:443
    reverse_proxy /management.ManagementService/* h2c://management:443
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
    # Dashboard
    reverse_proxy /* 192.168.65.1:3000
}
EOF
}

renderDockerCompose() {
  cat <<EOF
version: "3.4"
services:
  # Caddy reverse proxy
  caddy:
    image: caddy
    restart: unless-stopped
    networks: [ netbird ]
    ports:
      - '443:443'
      - '80:80'
      - '8080:8080'
    volumes:
      - netbird_caddy_data:/data
      - ./Caddyfile:/etc/caddy/Caddyfile
  #UI dashboard
  dashboard:
    image: wiretrustee/dashboard:latest
    restart: unless-stopped
    networks: [netbird]
    env_file:
      - ./dashboard.env
  # Signal
  signal:
    image: netbirdio/signal:latest
    restart: unless-stopped
    networks: [netbird]
  # Management
  management:
    image: netbirdio/management:latest
    restart: unless-stopped
    networks: [netbird]
    volumes:
      - netbird_management:/var/lib/netbird
      - ./management.json:/etc/netbird/management.json
    command: [
      "--port", "443",
      "--log-file", "console",
      "--disable-anonymous-metrics=$NETBIRD_DISABLE_ANONYMOUS_METRICS",
      "--single-account-mode-domain=$NETBIRD_MGMT_SINGLE_ACCOUNT_MODE_DOMAIN",
      "--dns-domain=$NETBIRD_MGMT_DNS_DOMAIN"
    ]
  # Coturn, AKA relay server
  coturn:
    image: coturn/coturn
    restart: unless-stopped
    domainname: netbird.relay.selfhosted
    volumes:
      - ./turnserver.conf:/etc/turnserver.conf:ro
    network_mode: host
    command:
      - -c /etc/turnserver.conf
  # Zitadel - identity provider
  zitadel:
    restart: 'always'
    networks: [netbird]
    image: 'ghcr.io/zitadel/zitadel:latest'
    command: 'start-from-init --masterkey "MasterkeyNeedsToHave32Characters" --tlsMode disabled'
    env_file:
      - ./zitadel.env
    depends_on:
      crdb:
        condition: 'service_healthy'
    volumes:
      - ./machinekey:/machinekey
    healthcheck:
      test: [ "CMD", "curl", "-f", "http://localhost:8080/debug/healthz" ]
      interval: '10s'
      timeout: '30s'
      retries: 5
      start_period: '20s'
  # CockroachDB for zitadel
  crdb:
    restart: 'always'
    networks: [netbird]
    image: 'cockroachdb/cockroach:v22.2.2'
    command: 'start-single-node --insecure'
    healthcheck:
      test: [ "CMD", "curl", "-f", "http://localhost:8080/health?ready=1" ]
      interval: '10s'
      timeout: '30s'
      retries: 5
      start_period: '20s'

volumes:
  netbird_management:
  netbird_caddy_data:
  netbird_zitadel_key:

networks:
  netbird:
EOF
}

renderTurnServerConf() {
  cat <<EOF
listening-port=3478
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

