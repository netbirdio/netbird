#!/bin/bash

set -e
create_new_project() {
  INSTANCE_URL=$1
  PAT=$2
  PROJECT_NAME="NETBIRD"

  RESPONSE=$(
    curl -X POST "$INSTANCE_URL/management/v1/projects" \
      -H "Authorization: Bearer $PAT" \
      -H "Content-Type: application/json" \
      -d '{"name": "'"$PROJECT_NAME"'"}'
  )
  echo "$RESPONSE" | jq -r '.id'
}

create_new_application() {
  INSTANCE_URL=$1
  PAT=$2
  APPLICATION_NAME="netbird"

  RESPONSE=$(
    curl -X POST "$INSTANCE_URL/management/v1/projects/$PROJECT_ID/apps/oidc" \
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
  echo "$RESPONSE" | jq -r '.clientId'
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
}

configure_zitadel_instance