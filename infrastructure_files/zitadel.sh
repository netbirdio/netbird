#!/bin/bash

configure_zitadel_instance() {
   # extract zitadel instance url
  INSTANCE_URL=$(echo "$NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT" | sed 's/\/\.well-known\/openid-configuration//')
  DOC_URL="https://netbird.io/docs/integrations/identity-providers/self-hosted/using-netbird-with-zitadel#step-4-create-a-service-user"
  
  echo ""
  printf "configuring zitadel instance: $INSTANCE_URL \n \
  before proceeding, please create a new service account for authorization by following the instructions (step 4 and 5
  ) in the documentation at %s\n"  "$DOC_URL"
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

  PROJECT_NAME="NETBIRD"
  APPLICATION_NAME="netbird"
 
  # get an access token from zitadel
  echo "retrieving access token from zitadel"
  ACCESS_TOKEN=$(curl -X POST "$INSTANCE_URL/oauth/v2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&scope=urn:zitadel:iam:org:project:id:zitadel:aud&client_id=$ZITADEL_CLIENT_ID&client_secret=$ZITADEL_CLIENT_SECRET" \
    | jq -r '.access_token')

  # create the zitadel project
  echo "creating $PROJECT_NAME project in zitadel"
  PROJECT_ID=$(curl -X POST "$INSTANCE_URL/management/v1/projects" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name": "'"$PROJECT_NAME"'"}' \
    | jq -r '.id')

  ZITADEL_DEV_MODE=false
  if [[ $NETBIRD_DOMAIN == *"localhost"* ]]
  then
    BASE_REDIRECT_URL="http://$NETBIRD_DOMAIN"
    ZITADEL_DEV_MODE=true
  else
    BASE_REDIRECT_URL="https://$NETBIRD_DOMAIN"
  fi

  # create zitadel spa application
  echo "creating $APPLICATION_NAME spa application in zitadel"
  APPLICATION_CLIENT_ID=$(curl -X POST  "$INSTANCE_URL/management/v1/projects/$PROJECT_ID/apps/oidc" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
  "name": "'"$APPLICATION_NAME"'",
  "redirectUris": [
    "'"$BASE_REDIRECT_URL"'/auth"
  ],
  "responseTypes": [
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
}' \
    | jq -r '.clientId'
)
}