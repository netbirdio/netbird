#!/usr/bin/env bash
set -eEuo pipefail

: ${NB_ENTRYPOINT_SERVICE_TIMEOUT:="5"}
: ${NB_ENTRYPOINT_LOGIN_TIMEOUT:="1"}
NETBIRD_BIN="${NETBIRD_BIN:-"netbird"}"
export NB_LOG_FILE="${NB_LOG_FILE:-"console:/var/log/netbird/client.log"}"
service_pids=()
log_file_path=""

_log() {
  # mimic Go logger's output for easier parsing
  # 2025-04-15T21:32:00+08:00 INFO client/internal/config.go:495: setting notifications to disabled by default
  printf "$(date -Isec) ${1} ${BASH_SOURCE[1]}:${BASH_LINENO[1]}: ${2}\n" "${@:3}" >&2
}

info() {
  _log INFO "$@"
}

warn() {
  _log WARN "$@"
}

on_exit() {
  info "Shutting down NetBird daemon..."
  if test "${#service_pids[@]}" -gt 0; then
    info "terminating service process PIDs: ${service_pids[*]}"
    kill -TERM "${service_pids[@]}" 2>/dev/null || true
    wait "${service_pids[@]}" 2>/dev/null || true
  else
    info "there are no service processes to terminate"
  fi
}

on_signal_propagate() {
  local signal="${1}"
  if test "${#service_pids[@]}" -gt 0; then
    info "Propagating ${signal} to NetBird daemon..."
    kill -"${signal}" "${#service_pids[@]}"
  fi
}

wait_for_message() {
  local timeout="${1}" message="${2}"
  if test "${timeout}" -eq 0; then
    info "not waiting for info message '${message}' due to zero timeout."
  elif test -n "${log_file_path}"; then
    info "waiting for info message '${message}' for ${timeout} seconds..."
    timeout "${timeout}" grep -q "${message}" <(tail -F "${log_file_path}" 2>/dev/null)
  else
    info "log file unsupported, sleeping for ${timeout} seconds..."
    sleep "${timeout}"
  fi
}

wait_for_daemon_startup() {
  local timeout="${1}" log_files_string="${2}"
  local log_file daemon_started=false
  while read -r log_file; do
    if test "${daemon_started}" = "true"; then
      continue
    fi
    case "${log_file}" in
    console | syslog | docker | stderr)
      warn "log file '${log_file}' parsing is not supported by debug bundles"
      warn "please consider removing the \$NB_LOG_FILE or setting it to real file, before gathering debug bundles."
      ;;
    *)
      log_file_path="${log_file}"

      if ! wait_for_message "${timeout}" "started daemon server"; then
        warn "log line containing 'started daemon server' not found after ${timeout} seconds"
        warn "daemon failed to start, exiting..."
        exit 1
      fi
      daemon_started=true
      ;;
    esac
  done < <(sed 's#:#\n#g' <<<"${log_files_string}")

  if test "${daemon_started}" != "true"; then
    warn "daemon service startup not discovered, sleeping ${timeout} instead"
    sleep "${timeout}"
  fi
}

login_if_needed() {
  local timeout="${1}"

  if test -n "${log_file_path}" && wait_for_message "${timeout}" 'peer has been successfully registered'; then
    info "already logged in, skipping 'netbird up'..."
  else
    info "logging in..."
    "${NETBIRD_BIN}" up
  fi
}

main() {
  trap 'on_exit' SIGTERM SIGINT EXIT
  "${NETBIRD_BIN}" service run &
  service_pids+=("$!")
  info "registered new service process 'netbird service run', currently running: ${service_pids[*]}"

  wait_for_daemon_startup "${NB_ENTRYPOINT_SERVICE_TIMEOUT}" "${NB_LOG_FILE}"
  login_if_needed "${NB_ENTRYPOINT_LOGIN_TIMEOUT}"

  wait "${service_pids[@]}"
}

main "$@"
