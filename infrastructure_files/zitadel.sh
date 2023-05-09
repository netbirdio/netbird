#!/bin/bash

set -e

request_jwt_token() {
  INSTANCE_URL=$1
  BODY="grant_type=client_credentials&scope=urn:zitadel:iam:org:project:id:zitadel:aud&client_id=$ZITADEL_CLIENT_ID&client_secret=$ZITADEL_CLIENT_SECRET"

  RESPONSE=$(
    curl -X POST "$INSTANCE_URL/oauth/v2/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "$BODY"
  )
  echo "$RESPONSE" | jq -r '.access_token'
}

create_new_project() {
  INSTANCE_URL=$1
  ACCESS_TOKEN=$2
  PROJECT_NAME="NETBIRD"

  RESPONSE=$(
    curl -X POST "$INSTANCE_URL/management/v1/projects" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"name": "'"$PROJECT_NAME"'"}'
  )
  echo "$RESPONSE" | jq -r '.id'
}

create_new_application() {
  INSTANCE_URL=$1
  ACCESS_TOKEN=$2
  APPLICATION_NAME="netbird"

  RESPONSE=$(
    curl -X POST "$INSTANCE_URL/management/v1/projects/$PROJECT_ID/apps/oidc" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
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
      "OIDC_GRANT_TYPE_AUTHORIZATION_CODE"
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
  # extract zitadel instance url
  INSTANCE_URL=$(echo "$NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT" | sed 's/\/\.well-known\/openid-configuration//')
  DOC_URL="https://netbird.io/docs/integrations/identity-providers/self-hosted/using-netbird-with-zitadel#step-4-create-a-service-user"

  echo ""
  printf "configuring zitadel instance: $INSTANCE_URL \n \
  before proceeding, please create a new service account for authorization by following the instructions (step 4 and 5
  ) in the documentation at %s\n" "$DOC_URL"
  echo "Please ensure that the new service account has 'Org Owner' permission in order for this to work."
  echo ""

  read -n 1 -s -r -p "press any key to continue..."
  echo ""

  # prompt the user to enter service account clientID
  echo ""
  read -r -p "enter service account ClientId: " ZITADEL_CLIENT_ID
  echo ""

  # Prompt the user to enter service account clientSecret
  read -r -p "enter service account ClientSecret: " ZITADEL_CLIENT_SECRET
  echo ""

  # get an access token from zitadel
  echo "retrieving access token from zitadel"
  ACCESS_TOKEN=$(request_jwt_token "$INSTANCE_URL")
  if [ "$ACCESS_TOKEN" = "null" ]; then
    echo "failed requesting access token"
    exit 1
  fi

  #  create the zitadel project
  echo "creating new zitadel project"
  PROJECT_ID=$(create_new_project "$INSTANCE_URL" "$ACCESS_TOKEN")
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
  APPLICATION_CLIENT_ID=$(create_new_application "$INSTANCE_URL" "$ACCESS_TOKEN")
  if [ "$APPLICATION_CLIENT_ID" = "null" ]; then
    echo "failed creating new zitadel spa application"
    exit 1
  fi
}
