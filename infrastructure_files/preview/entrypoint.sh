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
#   NB_PREVIEW_OWNER_EMAIL          bootstrap admin. Optional, no default, and
#   NB_PREVIEW_OWNER_PASSWORD_HASH  its bcrypt hash. Both or neither: a suite
#                                   signs in as the account it seeded, so a
#                                   preview needs no bootstrap user.
#   NB_PREVIEW_AUTH_SECRET          shared secret for relay authentication.
#   NB_PREVIEW_STORE_ENCRYPTION_KEY base64 32-byte key. Fixed by default so a
#                                   redeploy can still read what the previous
#                                   boot encrypted.
#   NB_PREVIEW_COOKIE_ENCRYPTION_KEY base64 32-byte key for Dex session cookies.
#
# The two encryption keys have fixed defaults on purpose, so a redeploy can
# still read what the previous boot wrote. They belong to throwaway preview
# environments only - never point them at anything a real user or real data can
# reach. The owner credentials have no default at all.
#
set -euo pipefail

# Every value below is interpolated into a double-quoted YAML scalar, where a
# quote ends the string and a backslash starts an escape. A database URL whose
# password carries either would render a config that does not parse, or - worse
# - one that parses to a different value.
yaml_escape() {
  local v="$1"
  v="${v//\\/\\\\}"
  v="${v//\"/\\\"}"
  printf '%s' "${v}"
}

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

if [[ "${SCHEME}" == "https" ]]; then DEFAULT_PORT=443; else DEFAULT_PORT=80; fi

if [[ "${HOSTPORT}" == *:* ]]; then
  EXPOSED_HOSTPORT="${HOSTPORT}"
else
  EXPOSED_HOSTPORT="${HOSTPORT}:${DEFAULT_PORT}"
fi

# A browser drops the scheme's default port before it sends a redirect back,
# and Dex matches a registered redirect URI as an exact string. Leaving :443 in
# the origin would register a URI no browser ever produces, and every login
# would fail on invalid_redirect_uri. The peers' address keeps its explicit
# port, which is why only the origin is trimmed.
ORIGIN_HOSTPORT="${HOSTPORT%:${DEFAULT_PORT}}"

ORIGIN="${SCHEME}://${ORIGIN_HOSTPORT}"
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

# The bootstrap owner is optional and has no default: a credential committed
# here would be the same one on every deployment that ever used this file. A
# suite signs in as the account it seeded, not as this user, so leaving both
# unset is the normal case. Supply the pair to get a bootstrap admin.
OWNER_EMAIL="${NB_PREVIEW_OWNER_EMAIL:-}"
OWNER_PASSWORD_HASH="${NB_PREVIEW_OWNER_PASSWORD_HASH:-}"
if [[ -n "${OWNER_EMAIL}${OWNER_PASSWORD_HASH}" && ( -z "${OWNER_EMAIL}" || -z "${OWNER_PASSWORD_HASH}" ) ]]; then
  echo "netbird-preview: NB_PREVIEW_OWNER_EMAIL and NB_PREVIEW_OWNER_PASSWORD_HASH must be set together" >&2
  exit 1
fi

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
  exposedAddress: "$(yaml_escape "${EXPOSED_ADDRESS}")"
  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "$(yaml_escape "${LOG_LEVEL}")"
  logFile: "console"
  authSecret: "$(yaml_escape "${AUTH_SECRET}")"
  dataDir: "$(yaml_escape "${DATA_DIR}")"
  disableAnonymousMetrics: true
  disableGeoliteUpdate: true

  # TLS is terminated by the preview ingress, so the server speaks plain HTTP
  # (h2c) on its listen port. Pointing at an external STUN server also keeps the
  # local STUN listener off UDP/3478, which a preview never exposes anyway.
  stuns:
    - uri: "stun:stun.netbird.io:3478"

  auth:
    issuer: "$(yaml_escape "${ORIGIN}")/oauth2"
    localAuthDisabled: false
    sessionCookieEncryptionKey: "$(yaml_escape "${COOKIE_ENCRYPTION_KEY}")"
    dashboardRedirectURIs:
      # The dashboard is a static export behind nginx, so its own default return
      # paths are hash fragments - a real path like /nb-auth is a 404 there. Dex
      # matches a redirect URI by exact string, so both forms are registered:
      # the fragments the dashboard uses, and the paths a dashboard build that
      # does serve them would use.
      - "$(yaml_escape "${DASHBOARD_ORIGIN}")/#callback"
      - "$(yaml_escape "${DASHBOARD_ORIGIN}")/#silent-callback"
      - "$(yaml_escape "${DASHBOARD_ORIGIN}")/nb-auth"
      - "$(yaml_escape "${DASHBOARD_ORIGIN}")/nb-silent-auth"
      - "$(yaml_escape "${ORIGIN}")/oauth2/callback"
    dashboardPostLogoutRedirectURIs:
      - "$(yaml_escape "${DASHBOARD_ORIGIN}")/"
    cliRedirectURIs:
      - "http://localhost:53000/"
YAML

  if [[ -n "${OWNER_EMAIL}" && -n "${OWNER_PASSWORD_HASH}" ]]; then
    cat <<YAML
    owner:
      email: "$(yaml_escape "${OWNER_EMAIL}")"
      password: "$(yaml_escape "${OWNER_PASSWORD_HASH}")"
YAML
  fi

  cat <<YAML

  store:
    engine: "${STORE_ENGINE}"
    encryptionKey: "$(yaml_escape "${STORE_ENCRYPTION_KEY}")"
YAML

  if [[ -n "${DATABASE_URL}" ]]; then
    printf '    dsn: "%s"\n' "$(yaml_escape "${DATABASE_URL}")"
  fi

  cat <<YAML

  reverseProxy:
    trustedHTTPProxiesCount: 1
YAML
} > "${CONFIG_PATH}"

echo "netbird-preview: origin=${ORIGIN} dashboard=${DASHBOARD_ORIGIN} exposed=${EXPOSED_ADDRESS} store=${STORE_ENGINE} listen=:${PORT}"

exec /go/bin/netbird-server --config "${CONFIG_PATH}" "$@"
