#!/bin/bash
#
# SYNOPSIS
#   Push the NetBird MDM policy to a macOS device via JumpCloud Commands.
#
# DESCRIPTION
#   This is the macOS counterpart of docs/netbird-policy.reg.ps1.
#   It writes the values declared in the "POLICY VALUES" block below to
#   the managed-preferences plist that the NetBird daemon's
#   client/mdm/policy_darwin.go loader reads on every 1-minute MDM
#   reload tick:
#
#       /Library/Managed Preferences/io.netbird.client.plist
#
#   Once the plist lands, the daemon picks up the new values without
#   restart (the ticker calls Config.apply() → applyMDMPolicy() and
#   restarts the engine on diff).
#
# DEPLOYMENT (JumpCloud)
#   1. Admin Console -> Device Management -> Commands -> +.
#   2. Type: Mac, Shell, Run as: root.
#   3. Paste this file verbatim into the command body.
#   4. Bind to the target system group, save, run.
#
# IMPORTANT: PERSISTENCE
#   macOS wipes /Library/Managed Preferences/ at every boot on devices
#   that are NOT MDM-enrolled. For a persistent fleet rollout, push the
#   companion docs/netbird-macos.mobileconfig as a Custom Configuration
#   Profile (Admin Console -> MDM -> Mac Custom Configuration Profiles)
#   instead of this script. Use this script when:
#     - the device is MDM-enrolled (file survives reboots), or
#     - you need a one-shot test push before reboot, or
#     - you orchestrate via JumpCloud Commands and want the same
#       variable-driven workflow as the Windows .ps1 sibling.
#
# IDEMPOTENCY: re-running with the same values is a no-op from the
# daemon's point of view (the 1-minute reload ticker diff returns empty).
#
# SECURITY: PreSharedKey (and any secret-bearing debugBundleUploadURL) is
#   redacted in this script's log output, and the installed plist is 0600
#   root:wheel so its values are not readable by local non-root users.

set -euo pipefail

### POLICY VALUES — EDIT THIS BLOCK ###########################################
#
# Set each variable below to the desired value. Set to empty string ""
# or to NULL to omit a key entirely (the daemon treats an absent key
# as "no enforcement" for that field). Booleans use "true"/"false"
# (lowercase). Integers as decimal.
#
# Reference for key names + accepted values:
#   client/mdm/policy.go (Key* constants)
#   docs/netbird-macos.mobileconfig (sample profile)
#   docs/netbird.admx + .adml (Windows ADMX schema)
#
NULL='__UNSET__'
managementURL='https://api.netbird.io:443'
preSharedKey="$NULL"                       # secret; redacted in log
allowServerSSH='true'
allowRemoteJobs="$NULL"
debugBundleUploadURL="$NULL"                # HTTPS URL with a host; overrides management
blockInbound="$NULL"
disableAutoConnect="$NULL"
disableAutostart="$NULL"
disableClientRoutes="$NULL"
disableServerRoutes="$NULL"
disableMetricsCollection="$NULL"
disableUpdateSettings="$NULL"
disableProfiles="$NULL"
disableNetworks="$NULL"
disableAdvancedView="$NULL"           # tristate at the daemon
rosenpassEnabled="$NULL"
rosenpassPermissive="$NULL"
wireguardPort='51820'
splitTunnelMode="$NULL"                    # "allow" or "disallow", Android-only at the daemon level
splitTunnelApps="$NULL"                    # comma-separated app IDs, Android-only
##############################################################################

readonly PLIST_DIR='/Library/Managed Preferences'
readonly PLIST_PATH="$PLIST_DIR/io.netbird.client.plist"
readonly LOG_TAG='netbird-mdm'

# log sends a message to the system logger using the configured tag and echoes the message to stdout prefixed by an ISO 8601 UTC timestamp and the tag.
log() {
  /usr/bin/logger -t "$LOG_TAG" "$*"
  printf '%s [%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$LOG_TAG" "$*"
}

# is_set returns success if the provided value is non-empty and is not equal to the special NULL marker.
is_set() {
  local value="$1"
  [[ -n "$value" && "$value" != "$NULL" ]]
}

# start_plist creates the temporary plist file at "$PLIST_PATH.tmp" containing the XML plist header and opening `<dict>` for the policy plist.
start_plist() {
  cat > "$PLIST_PATH.tmp" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
EOF
}

# end_plist appends the closing `</dict>` and `</plist>` tags to the temporary plist file.
end_plist() {
  cat >> "$PLIST_PATH.tmp" <<'EOF'
</dict>
</plist>
EOF
}

# emit_string appends a plist `<key>`/`<string>` entry for the given key and value to "$PLIST_PATH.tmp", XML-escaping `&`, `<`, and `>`, and logs the assignment (masking the logged value as `********** (secret)` for secret keys — `preSharedKey` and `debugBundleUploadURL`, which can embed credentials or a signed query token).
emit_string() {
  local key="$1" value="$2" log_value="$2"
  # Escape XML entities in the value
  local escaped
  escaped="$(printf '%s' "$value" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')"
  printf '    <key>%s</key>\n    <string>%s</string>\n' "$key" "$escaped" >> "$PLIST_PATH.tmp"
  case "$key" in
    preSharedKey|debugBundleUploadURL) log_value='********** (secret)' ;;
    *) ;;
  esac
  log "set $key = $log_value"
}

# is_bool returns success if the value is an accepted boolean token.
is_bool() {
  local value="$1"
  case "$value" in
    true|True|TRUE|1|yes|false|False|FALSE|0|no) return 0 ;;
    *) return 1 ;;
  esac
}

# emit_bool writes a boolean plist entry for a key when the provided value matches
# an accepted boolean token; logs an error and skips the key on invalid input.
# It returns success even on invalid input (like emit_int) so a single typo in one
# boolean does not abort the whole policy push under `set -euo pipefail`. Callers
# that must fail closed on an invalid value (e.g. allowRemoteJobs) validate with
# is_bool before calling and substitute a safe default themselves.
emit_bool() {
  local key="$1" value="$2"
  local xml_bool
  case "$value" in
    true|True|TRUE|1|yes)  xml_bool='<true/>'  ; value='true'  ;;
    false|False|FALSE|0|no) xml_bool='<false/>' ; value='false' ;;
    *) log "invalid boolean for $key: $value (must be true/false); skipping"; return ;;
  esac
  printf '    <key>%s</key>\n    %s\n' "$key" "$xml_bool" >> "$PLIST_PATH.tmp"
  log "set $key = $value"
}

# emit_int validates that VALUE contains only decimal digits and, if valid, appends an `<integer>` plist entry for KEY to the temporary plist (`$PLIST_PATH.tmp`) and logs the assignment; on invalid input it logs a skip and does not emit the key.
emit_int() {
  local key="$1" value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    log "invalid integer for $key: $value (must be decimal); skipping"
    return
  fi
  printf '    <key>%s</key>\n    <integer>%s</integer>\n' "$key" "$value" >> "$PLIST_PATH.tmp"
  log "set $key = $value"
}

# main builds the NetBird MDM plist from configured policy variables, validates and installs it to /Library/Managed Preferences/io.netbird.client.plist (root:wheel, 600 — the daemon reads it directly as root, so it need not be world-readable) and optionally triggers the NetBird daemon to reload.
main() {
  log "applying NetBird MDM policy to $PLIST_PATH"
  # Restrict the temp plist while it is being built: it carries the same
  # secret-bearing values as the final file, which is installed 0600 below.
  umask 077
  /bin/mkdir -p "$PLIST_DIR"
  start_plist
  # Force 0600 on the temp file explicitly: start_plist writes it with a
  # truncating redirect, which keeps an existing file's mode, so a leftover
  # 0644 tmp from an interrupted run would not be tightened by umask alone.
  # start_plist only wrote the header so far — the secret-bearing values are
  # appended after this point.
  /bin/chmod 600 "$PLIST_PATH.tmp"

  is_set "$managementURL"             && emit_string  managementURL             "$managementURL"
  is_set "$preSharedKey"              && emit_string  preSharedKey              "$preSharedKey"
  is_set "$allowServerSSH"            && emit_bool    allowServerSSH            "$allowServerSSH"
  # Fail closed: an invalid allowRemoteJobs value must not drop the key and
  # leave a conflicting local opt-in active — enforce the safe default (false).
  if is_set "$allowRemoteJobs"; then
    if is_bool "$allowRemoteJobs"; then
      emit_bool allowRemoteJobs "$allowRemoteJobs"
    else
      log "invalid boolean for allowRemoteJobs: $allowRemoteJobs; enforcing safe default (false)"
      emit_bool allowRemoteJobs false
    fi
  fi
  is_set "$debugBundleUploadURL"      && emit_string  debugBundleUploadURL      "$debugBundleUploadURL"
  is_set "$blockInbound"              && emit_bool    blockInbound              "$blockInbound"
  is_set "$disableAutoConnect"        && emit_bool    disableAutoConnect        "$disableAutoConnect"
  is_set "$disableAutostart"          && emit_bool    disableAutostart          "$disableAutostart"
  is_set "$disableClientRoutes"       && emit_bool    disableClientRoutes       "$disableClientRoutes"
  is_set "$disableServerRoutes"       && emit_bool    disableServerRoutes       "$disableServerRoutes"
  is_set "$disableMetricsCollection"  && emit_bool    disableMetricsCollection  "$disableMetricsCollection"
  is_set "$disableUpdateSettings"     && emit_bool    disableUpdateSettings     "$disableUpdateSettings"
  is_set "$disableProfiles"           && emit_bool    disableProfiles           "$disableProfiles"
  is_set "$disableNetworks"           && emit_bool    disableNetworks           "$disableNetworks"
  is_set "$disableAdvancedView"       && emit_bool    disableAdvancedView       "$disableAdvancedView"
  is_set "$rosenpassEnabled"          && emit_bool    rosenpassEnabled          "$rosenpassEnabled"
  is_set "$rosenpassPermissive"       && emit_bool    rosenpassPermissive       "$rosenpassPermissive"
  is_set "$wireguardPort"             && emit_int     wireguardPort             "$wireguardPort"
  is_set "$splitTunnelMode"           && emit_string  splitTunnelMode           "$splitTunnelMode"
  is_set "$splitTunnelApps"           && emit_string  splitTunnelApps           "$splitTunnelApps"

  end_plist

  if ! /usr/bin/plutil -lint "$PLIST_PATH.tmp" >/dev/null 2>&1; then
    log "ERROR: generated plist failed plutil lint; not installing"
    /usr/bin/plutil -lint "$PLIST_PATH.tmp" >&2 || true
    /bin/rm -f "$PLIST_PATH.tmp"
    exit 1
  fi

  /bin/mv -f "$PLIST_PATH.tmp" "$PLIST_PATH"
  /usr/sbin/chown root:wheel "$PLIST_PATH"
  # 0600, not 0644: the daemon's loader (client/mdm/policy_darwin.go) opens the
  # plist directly as root, so it does not need to be world-readable. Restricting
  # it keeps secret-bearing values (preSharedKey, a signed debugBundleUploadURL)
  # from any local non-root user. The loader's only mode check refuses a
  # world-writable file, which 0600 satisfies.
  /bin/chmod 600 "$PLIST_PATH"

  log "policy installed; NetBird daemon will pick it up within the next 1-minute reload tick"

  # Optional: kick the daemon for an immediate apply. Safe — does
  # nothing on a host where NetBird is not yet installed.
  /bin/launchctl kickstart -k system/io.netbird.client 2>/dev/null || true
}

main "$@"
