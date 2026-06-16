#!/usr/bin/env bash
#
# Dev helper for testing NetBird's MDM policy on macOS.
#
# Edits /Library/Managed Preferences/io.netbird.client.plist (the same path the
# OS would populate from a real Configuration Profile). The MDM ticker observes
# the change within ≤60s; the daemon restarts the engine itself in-process.
#
# Usage:
#   ./mdm-toggle.sh tui                    # interactive terminal UI
#   ./mdm-toggle.sh show                   # print current plist
#   ./mdm-toggle.sh clear                  # wipe (delete) the plist
#   ./mdm-toggle.sh restart                # kick the daemon
#   ./mdm-toggle.sh logs [-f]              # tail daemon log filtered for MDM lines
#   ./mdm-toggle.sh verify                 # plist + recent MDM log lines
#
# Known keys (see client/mdm/policy.go):
#   managementURL preSharedKey wireguardPort rosenpassEnabled rosenpassPermissive
#   disableClientRoutes disableServerRoutes allowServerSSH disableAutoConnect
#   blockInbound disableMetricsCollection splitTunnelMode splitTunnelApps
#   disableProfiles disableNetworks disableUpdateSettings disableAdvancedView

set -euo pipefail

PLIST="/Library/Managed Preferences/io.netbird.client.plist"
LAUNCHD_LABEL="system/netbird"
DAEMON_LOG="/var/log/netbird/client.log"
LOG_GREP='MDM|mdm|policy|engine restart|config_changed|managed|RegisterUILog'

die() { echo "error: $*" >&2; exit 1; }

require_sudo() {
  if [[ $EUID -ne 0 ]]; then
    exec sudo --preserve-env=HOME "$0" "$@"
  fi
}

ensure_plist() {
  if [[ ! -f "$PLIST" ]]; then
    mkdir -p "$(dirname "$PLIST")"
    /usr/libexec/PlistBuddy -c "Save" "$PLIST" >/dev/null 2>&1 || \
      /bin/cat >"$PLIST" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict/></plist>
EOF
    chown root:wheel "$PLIST"
    chmod 0644 "$PLIST"
  fi
}

restart_daemon() {
  echo "kicking daemon ($LAUNCHD_LABEL)..."
  launchctl kickstart -k "$LAUNCHD_LABEL"
}

cmd_show() {
  if [[ ! -f "$PLIST" ]]; then
    echo "(no plist at $PLIST — MDM not active)"
    return
  fi
  echo "# $PLIST"
  /usr/libexec/PlistBuddy -c "Print" "$PLIST"
}

cmd_clear() {
  if [[ -f "$PLIST" ]]; then
    rm -f "$PLIST"
    echo "removed $PLIST"
  else
    echo "(already absent)"
  fi
}

cmd_logs() {
  local follow=0
  [[ "${1:-}" == "-f" || "${1:-}" == "--follow" ]] && follow=1
  [[ -f "$DAEMON_LOG" ]] || die "daemon log not found at $DAEMON_LOG"
  if [[ $follow -eq 1 ]]; then
    echo "# tailing $DAEMON_LOG (Ctrl-C to stop) — filter: $LOG_GREP"
    tail -F "$DAEMON_LOG" | grep -E --line-buffered --color=always "$LOG_GREP"
  else
    echo "# last MDM-relevant lines from $DAEMON_LOG"
    grep -E --color=always "$LOG_GREP" "$DAEMON_LOG" | tail -30
  fi
}

cmd_verify() {
  echo "=== plist ==="
  if [[ -f "$PLIST" ]]; then
    /usr/libexec/PlistBuddy -c "Print" "$PLIST"
  else
    echo "(no plist at $PLIST — MDM not active)"
  fi
  echo
  echo "=== daemon log (last 20 MDM-relevant lines) ==="
  if [[ -f "$DAEMON_LOG" ]]; then
    grep -E --color=always "$LOG_GREP" "$DAEMON_LOG" | tail -20 \
      || echo "(no MDM-related entries yet — wait up to 60s for next ticker fire)"
  else
    echo "(daemon log not found at $DAEMON_LOG)"
  fi
}

cmd_tui() {
  local KEYS=(
    managementURL preSharedKey wireguardPort splitTunnelMode splitTunnelApps
    rosenpassEnabled rosenpassPermissive disableClientRoutes disableServerRoutes
    allowServerSSH disableAutoConnect blockInbound disableMetricsCollection
    disableAdvancedView disableProfiles disableNetworks disableUpdateSettings
  )
  local TYPES=(
    string string integer string array
    bool bool bool bool
    bool bool bool bool
    bool bool bool bool
  )

  # ANSI helpers; bail to plain text when stdout isn't a tty.
  local C_RESET="" C_BOLD="" C_DIM="" C_GREEN="" C_RED="" C_YELLOW="" C_CYAN=""
  if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
  fi

  read_value() {
    local key="$1"
    [[ -f "$PLIST" ]] || { echo ""; return; }
    /usr/libexec/PlistBuddy -c "Print :$key" "$PLIST" 2>/dev/null || true
  }

  render_value() {
    local raw="$1" type="$2"
    if [[ -z "$raw" ]]; then
      printf '%s—%s' "$C_DIM" "$C_RESET"
      return
    fi
    case "$type" in
      bool)
        if [[ "$raw" == "true" ]]; then
          printf '%s✔ true%s'  "$C_GREEN" "$C_RESET"
        else
          printf '%s✘ false%s' "$C_RED" "$C_RESET"
        fi ;;
      array)
        printf '%s[%s]%s' "$C_CYAN" "$(echo "$raw" | tr '\n' ' ' | tr -s ' ')" "$C_RESET" ;;
      *)
        printf '%s%s%s' "$C_YELLOW" "$raw" "$C_RESET" ;;
    esac
  }

  render_screen() {
    clear
    printf '%s════ NetBird MDM Tester ════%s\n' "$C_BOLD" "$C_RESET"
    printf '%splist:%s %s   %sdaemon log:%s %s\n\n' \
      "$C_DIM" "$C_RESET" "$PLIST" "$C_DIM" "$C_RESET" "$DAEMON_LOG"
    local i
    for i in "${!KEYS[@]}"; do
      local key="${KEYS[$i]}" type="${TYPES[$i]}" raw
      raw="$(read_value "$key")"
      printf '  %s[%2d]%s %-30s %s%s(%s)%s\n' \
        "$C_BOLD" $((i+1)) "$C_RESET" "$key" \
        "$(render_value "$raw" "$type")" \
        "$C_DIM" "$type" "$C_RESET"
    done
    printf '\n'
    printf '  %s[k]%s kick daemon   %s[c]%s clear plist   %s[l]%s show recent log   %s[r]%s refresh   %s[q]%s quit\n' \
      "$C_BOLD" "$C_RESET" "$C_BOLD" "$C_RESET" "$C_BOLD" "$C_RESET" "$C_BOLD" "$C_RESET" "$C_BOLD" "$C_RESET"
    printf '\n'
  }

  edit_field() {
    local idx="$1"
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || (( idx < 1 || idx > ${#KEYS[@]} )); then
      echo "  (out of range)"; sleep 0.6; return
    fi
    local key="${KEYS[$((idx-1))]}" type="${TYPES[$((idx-1))]}" cur
    cur="$(read_value "$key")"
    ensure_plist
    case "$type" in
      bool)
        # Cycle: unset → true → false → unset
        case "$cur" in
          "")       /usr/libexec/PlistBuddy -c "Add :$key bool true"     "$PLIST" ;;
          "true")   /usr/libexec/PlistBuddy -c "Delete :$key"            "$PLIST"
                    /usr/libexec/PlistBuddy -c "Add :$key bool false"    "$PLIST" ;;
          "false")  /usr/libexec/PlistBuddy -c "Delete :$key"            "$PLIST" ;;
        esac ;;
      array)
        echo "  current: $cur"
        read -r -p "  new array (space-separated, empty to unset): " line
        /usr/libexec/PlistBuddy -c "Delete :$key" "$PLIST" 2>/dev/null || true
        if [[ -n "$line" ]]; then
          /usr/libexec/PlistBuddy -c "Add :$key array" "$PLIST"
          local i=0 v
          for v in $line; do
            /usr/libexec/PlistBuddy -c "Add :$key:$i string $v" "$PLIST"
            i=$((i+1))
          done
        fi ;;
      *)
        echo "  current: $cur"
        read -r -p "  new $type (empty to unset): " line
        /usr/libexec/PlistBuddy -c "Delete :$key" "$PLIST" 2>/dev/null || true
        if [[ -n "$line" ]]; then
          /usr/libexec/PlistBuddy -c "Add :$key $type $line" "$PLIST"
        fi ;;
    esac
  }

  show_recent_log() {
    clear
    printf '%s── recent MDM-related daemon log lines ──%s\n' "$C_BOLD" "$C_RESET"
    if [[ -f "$DAEMON_LOG" ]]; then
      grep -E --color=always "$LOG_GREP" "$DAEMON_LOG" | tail -25 \
        || echo "(no MDM-related entries yet)"
    else
      echo "(daemon log not found at $DAEMON_LOG)"
    fi
    echo
    read -r -p "press enter to return " _
  }

  echo "starting MDM tester (Ctrl-C or q to quit)"
  while true; do
    render_screen
    read -r -p "> " choice || break
    case "$choice" in
      q|quit|exit) break ;;
      k|kick)      restart_daemon; sleep 0.6 ;;
      c|clear)     cmd_clear; sleep 0.6 ;;
      l|logs)      show_recent_log ;;
      r|"")        : ;;  # redraw
      *)           edit_field "$choice" ;;
    esac
  done
  echo "bye"
}

sub="${1:-}"; shift || true

case "$sub" in
  show)    cmd_show "$@"; exit 0 ;;
  logs)    require_sudo "$sub" "$@"; cmd_logs   "$@"; exit 0 ;;
  verify)  require_sudo "$sub" "$@"; cmd_verify "$@"; exit 0 ;;
  tui)     require_sudo "$sub" "$@"; cmd_tui    "$@"; exit 0 ;;
  restart) require_sudo "$sub" "$@"; restart_daemon; exit 0 ;;
  clear)   require_sudo "$sub" "$@"; cmd_clear  "$@"; exit 0 ;;
  ""|-h|--help|help)
    sed -n '2,18p' "$0"
    ;;
  *) die "unknown subcommand: $sub (try --help)" ;;
esac
