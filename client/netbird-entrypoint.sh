#!/usr/bin/env bash
set -eEuo pipefail

: ${NB_ENTRYPOINT_SERVICE_TIMEOUT:="5"}
: ${NB_ENTRYPOINT_LOGIN_TIMEOUT:="1"}
: ${NB_ENTRYPOINT_TAIL_LOG_FILE:="true"}
NETBIRD_BIN="${NETBIRD_BIN:-"netbird"}"
export NB_LOG_FILE="${NB_LOG_FILE:-"/var/log/netbird/client.log"}"
service_pids=()
extra_pids=()

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
  if test "${#extra_pids[@]}" -gt 0; then
    info "terminating extra process PIDs: ${extra_pids[*]}"
    kill -TERM "${extra_pids[@]}" 2>/dev/null || true
    wait "${extra_pids[@]}" 2>/dev/null || true
  else
    info "there are no extra processes to terminate"
  fi
  exit 0
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
  elif test "${has_logfile}" = "true"; then
    info "waiting for info message '${message}' for ${timeout} seconds..."
    timeout "${timeout}" grep -q "${message}" <(tail -F "${NB_LOG_FILE}" 2>/dev/null)
  else
    info "log file unsupported, sleeping for ${timeout} seconds..."
    sleep "${timeout}"
  fi
}

main() {
  has_logfile="false"
  "${NETBIRD_BIN}" service run &
  service_pids+=("$!")
  info "registered new service process 'netbird service run', currently running: ${service_pids[*]}"

  trap 'signal_cleanup' SIGTERM SIGINT EXIT

  case "${NB_LOG_FILE}" in
  console | syslog)
    warn "\$NB_LOG_FILE='${NB_LOG_FILE}' parsing is not supported, sleeping for ${NB_ENTRYPOINT_SERVICE_TIMEOUT} instead."
    warn "please consider removing the \$NB_LOG_FILE or setting it to real file, before gathering debug bundles."
    sleep "${NB_ENTRYPOINT_SERVICE_TIMEOUT}"
    ;;
  *)
    has_logfile="true"
    if test "${NB_ENTRYPOINT_TAIL_LOG_FILE}" = "true"; then
      info "tailing ${NB_LOG_FILE}..."
      tail -F "${NB_LOG_FILE}" >&2 &
      extra_pids+=("$!")
      info "registered new extra process 'tail', currently running: ${extra_pids[*]}"
    fi

    if ! wait_for_message "${NB_ENTRYPOINT_SERVICE_TIMEOUT}" "started daemon server"; then
      warn "log line containing 'started daemon server' not found after ${NB_ENTRYPOINT_SERVICE_TIMEOUT} seconds"
      warn "daemon failed to start, exiting..."
      exit 1
    fi
    ;;
  esac

  if test "${has_logfile}" = "true" && wait_for_message "${NB_ENTRYPOINT_LOGIN_TIMEOUT}" 'peer has been successfully registered'; then
    info "already logged in, skipping 'netbird up'..."
  else
    info "logging in..."
    "${NETBIRD_BIN}" up
  fi

  wait "${service_pids[@]}"
}

main "$@"
