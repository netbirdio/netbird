#!/usr/bin/env bash
set -eEuo pipefail

: ${NB_ENTRYPOINT_SERVICE_TIMEOUT:="30"}
NETBIRD_BIN="${NETBIRD_BIN:-"netbird"}"
export NB_LOG_FILE="${NB_LOG_FILE:-"console,/var/log/netbird/client.log"}"
service_pids=()

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
    info "terminating service process IDs: ${service_pids[@]@Q}"
    kill -TERM "${service_pids[@]}" 2>/dev/null || true
    wait "${service_pids[@]}" 2>/dev/null || true
  else
    info "there are no service processes to terminate"
  fi
}

wait_for_daemon_startup() {
  local timeout="${1}"
  if [[ "${timeout}" -eq 0 ]]; then
    info "not waiting for daemon startup due to zero timeout."
    return
  fi

  local deadline=$((SECONDS + timeout))
  while [[ "${SECONDS}" -lt "${deadline}" ]]; do
    if "${NETBIRD_BIN}" status --check live 2>/dev/null; then
      return
    fi
    sleep 1
  done

  warn "daemon did not become responsive after ${timeout} seconds, exiting..."
  exit 1
}

connect() {
  info "running 'netbird up'..."
  "${NETBIRD_BIN}" up
  return $?
}

main() {
  trap 'on_exit' SIGTERM SIGINT EXIT
  "${NETBIRD_BIN}" service run &
  service_pids+=("$!")
  info "registered new service process 'netbird service run', currently running: ${service_pids[@]@Q}"

  wait_for_daemon_startup "${NB_ENTRYPOINT_SERVICE_TIMEOUT}"
  connect

  wait "${service_pids[@]}"
}

main "$@"
