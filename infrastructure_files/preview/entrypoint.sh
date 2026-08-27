#!/usr/bin/env bash
#
# Renders /etc/netbird/config.yaml for a preview deployment and starts the
# combined NetBird server. A preview's public URL is assigned at deploy time, so
# the issuer, redirect URIs, relay and signal addresses cannot be baked into a
# static config file.
#
# The container runs the combined server (Management, Signal, Relay and the
# embedded Dex IdP multiplexed onto one HTTP port). TLS is terminated by the
# preview ingress, so it speaks plain HTTP (h2c) and takes the public https://
# origin as NB_PREVIEW_PUBLIC_URL. /oauth2/... is Dex, /api/... is the management
# REST API, and everything else on the port is management gRPC.
#
# Inputs, all optional except the first:
#
#   NB_PREVIEW_PUBLIC_URL           required. The preview's public origin. Drives
#                                   the OIDC issuer, redirect URIs, the
#                                   relay/signal addresses and the management
#                                   DNS domain.
#   NB_PREVIEW_DASHBOARD_URL        origin the dashboard is served from, for its
#                                   OIDC redirect and post-logout URIs. Defaults
#                                   to this server's own origin, so a
#                                   server-only preview still boots.
#   NB_PREVIEW_DATABASE_URL         Postgres URL for the management store.
#                                   Falls back to SQLite in the data dir.
#   NB_PREVIEW_PORT                 listen port inside the container (8080).
#   NB_PREVIEW_DATA_DIR             data dir for the SQLite stores
#                                   (/var/lib/netbird).
#   NB_PREVIEW_LOG_LEVEL            log level for every embedded service (info).
#   NB_PREVIEW_OWNER_EMAIL          seeded owner (admin@preview.autonoma.app).
#   NB_PREVIEW_OWNER_PASSWORD_HASH  bcrypt hash of the owner password. Override
#                                   together with the email.
#   NB_PREVIEW_AUTH_SECRET          shared secret for relay authentication.
#   NB_PREVIEW_STORE_ENCRYPTION_KEY base64 32-byte key. Fixed by default so a
#                                   redeploy can still read what the previous
#                                   boot encrypted.
#   NB_PREVIEW_COOKIE_ENCRYPTION_KEY base64 32-byte key for Dex session cookies.
#
# The owner credentials and the two encryption keys have fixed defaults on
# purpose, so an automated suite can log in without being told a secret. They
# belong to throwaway preview environments only - never point them at anything a
# real user or real data can reach.
#
set -euo pipefail

CONFIG_PATH="${NB_PREVIEW_CONFIG_PATH:-/etc/netbird/config.yaml}"
DATA_DIR="${NB_PREVIEW_DATA_DIR:-/var/lib/netbird}"
PORT="${NB_PREVIEW_PORT:-8080}"
LOG_LEVEL="${NB_PREVIEW_LOG_LEVEL:-info}"

PUBLIC_URL="${NB_PREVIEW_PUBLIC_URL:-}"
if [[ -z "${PUBLIC_URL}" ]]; then
  echo "netbird-preview: NB_PREVIEW_PUBLIC_URL is required (the preview's public https URL)" >&2
  exit 1
fi

# Normalise the public URL into the two forms the config needs: the browser-facing
# origin (no default port, no trailing slash) and an explicit host:port for the
# addresses handed to peers.
PUBLIC_URL="${PUBLIC_URL%/}"
case "${PUBLIC_URL}" in
  http://*)  SCHEME="http";  HOSTPORT="${PUBLIC_URL#http://}" ;;
  https://*) SCHEME="https"; HOSTPORT="${PUBLIC_URL#https://}" ;;
  *)         SCHEME="https"; HOSTPORT="${PUBLIC_URL}" ;;
esac
HOSTPORT="${HOSTPORT%%/*}"

if [[ "${HOSTPORT}" == *:* ]]; then
  EXPOSED_HOSTPORT="${HOSTPORT}"
else
  if [[ "${SCHEME}" == "https" ]]; then
    EXPOSED_HOSTPORT="${HOSTPORT}:443"
  else
    EXPOSED_HOSTPORT="${HOSTPORT}:80"
  fi
fi

ORIGIN="${SCHEME}://${HOSTPORT}"
EXPOSED_ADDRESS="${SCHEME}://${EXPOSED_HOSTPORT}"

# The dashboard runs as its own container in the preview, so the origin a login
# returns to is the dashboard's, not the server's. It is only known at deploy
# time like everything else here, and it falls back to the server's own origin so
# a server-only preview keeps working unchanged.
DASHBOARD_URL="${NB_PREVIEW_DASHBOARD_URL:-${ORIGIN}}"
DASHBOARD_URL="${DASHBOARD_URL%/}"
case "${DASHBOARD_URL}" in
  http://*|https://*) DASHBOARD_ORIGIN="${DASHBOARD_URL}" ;;
  *)                  DASHBOARD_ORIGIN="https://${DASHBOARD_URL}" ;;
esac

OWNER_EMAIL="${NB_PREVIEW_OWNER_EMAIL:-admin@preview.autonoma.app}"
# bcrypt hash of the preview password "Preview!2345". Override both together.
OWNER_PASSWORD_HASH="${NB_PREVIEW_OWNER_PASSWORD_HASH:-\$2a\$10\$8QvbcceHoKU8Nywc55/2AegrlsWegSfNyRNyFiPpi/nbdbSqTxSrm}"

AUTH_SECRET="${NB_PREVIEW_AUTH_SECRET:-netbird-preview-relay-secret}"
# Fixed so a redeploy can still read data the previous boot encrypted.
STORE_ENCRYPTION_KEY="${NB_PREVIEW_STORE_ENCRYPTION_KEY:-P2ocmy5dR6iww9bp8qW4wdTn+gscLT5PWmt8jZ4PGis=}"
COOKIE_ENCRYPTION_KEY="${NB_PREVIEW_COOKIE_ENCRYPTION_KEY:-ni1MaosPE1d6nL4dP1B5osTmCBUnOUmhs8XX6fsdP1c=}"

# The management store goes to Postgres when the preview provides one; the small
# auxiliary stores (embedded IdP, activity events) stay on SQLite in the data dir.
DATABASE_URL="${NB_PREVIEW_DATABASE_URL:-}"
if [[ -n "${DATABASE_URL}" ]]; then
  STORE_ENGINE="postgres"
else
  STORE_ENGINE="sqlite"
fi

mkdir -p "${DATA_DIR}" "$(dirname "${CONFIG_PATH}")"

{
  cat <<YAML
# Generated by infrastructure_files/preview/entrypoint.sh - do not edit by hand.
server:
  listenAddress: ":${PORT}"
  exposedAddress: "${EXPOSED_ADDRESS}"
  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "${LOG_LEVEL}"
  logFile: "console"
  authSecret: "${AUTH_SECRET}"
  dataDir: "${DATA_DIR}"
  disableAnonymousMetrics: true
  disableGeoliteUpdate: true

  # TLS is terminated by the preview ingress, so the server speaks plain HTTP
  # (h2c) on its listen port. Pointing at an external STUN server also keeps the
  # local STUN listener off UDP/3478, which a preview never exposes anyway.
  stuns:
    - uri: "stun:stun.netbird.io:3478"

  auth:
    issuer: "${ORIGIN}/oauth2"
    localAuthDisabled: false
    sessionCookieEncryptionKey: "${COOKIE_ENCRYPTION_KEY}"
    dashboardRedirectURIs:
      # The dashboard is a static export behind nginx, so its own default return
      # paths are hash fragments - a real path like /nb-auth is a 404 there. Dex
      # matches a redirect URI by exact string, so both forms are registered:
      # the fragments the dashboard uses, and the paths a dashboard build that
      # does serve them would use.
      - "${DASHBOARD_ORIGIN}/#callback"
      - "${DASHBOARD_ORIGIN}/#silent-callback"
      - "${DASHBOARD_ORIGIN}/nb-auth"
      - "${DASHBOARD_ORIGIN}/nb-silent-auth"
      - "${ORIGIN}/oauth2/callback"
    dashboardPostLogoutRedirectURIs:
      - "${DASHBOARD_ORIGIN}/"
    cliRedirectURIs:
      - "http://localhost:53000/"
    owner:
      email: "${OWNER_EMAIL}"
      password: "${OWNER_PASSWORD_HASH}"

  store:
    engine: "${STORE_ENGINE}"
    encryptionKey: "${STORE_ENCRYPTION_KEY}"
YAML

  if [[ -n "${DATABASE_URL}" ]]; then
    printf '    dsn: "%s"\n' "${DATABASE_URL}"
  fi

  cat <<YAML

  reverseProxy:
    trustedHTTPProxiesCount: 1
YAML
} > "${CONFIG_PATH}"

echo "netbird-preview: origin=${ORIGIN} dashboard=${DASHBOARD_ORIGIN} exposed=${EXPOSED_ADDRESS} store=${STORE_ENGINE} listen=:${PORT}"

exec /go/bin/netbird-server --config "${CONFIG_PATH}" "$@"
