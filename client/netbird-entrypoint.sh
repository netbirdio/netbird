#!/usr/bin/env bash
set -eEuo pipefail

: ${NB_ENTRYPOINT_SERVICE_TIMEOUT:="5"}
: ${NB_ENTRYPOINT_LOGIN_TIMEOUT:="1"}
: ${NB_ENTRYPOINT_TAIL_LOG_FILE:="1"}
NETBIRD_BIN="${NETBIRD_BIN:-"netbird"}"
export NB_LOG_FILE="${NB_LOG_FILE:-"/var/log/netbird/client.log"}"
pids=()

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

signal_cleanup() {
  info "Shutting down NetBird daemon..."
  if test "${#pids[@]}" -gt 0; then
    kill -TERM "${pids[@]}" 2>/dev/null || true
    wait "${pids[@]}" 2>/dev/null || true
  fi
  exit 0
}

signal_propagate() {
  local signal="${1}"
  if test -n "${SERVICE_PID}"; then
    info "Propagating ${signal} to NetBird daemon..."
    kill -"${signal}" "${SERVICE_PID}"
  fi
}

wait_for_message() {
  local timeout="${1}" message="${2}"
  if test "${timeout}" == 0; then
    info "not waiting for info message '${message}' due to zero timeout."
  elif test "${has_logfile}" = 1; then
    info "waiting for info message '${message}' for ${timeout} seconds..."
    timeout "${timeout}" grep -q "${message}" <(tail -F "${NB_LOG_FILE}" 2>/dev/null)
  else
    info "log file unsupported, sleeping for ${timeout} seconds..."
    sleep "${timeout}"
  fi
}

main() {
  has_logfile="0"
  "${NETBIRD_BIN}" service run &
  SERVICE_PID="$!"
  pids+=("${SERVICE_PID}")

  trap 'signal_cleanup' SIGTERM SIGINT EXIT
  # TODO: do we actually handle any signals in `netbird service run`?
  #trap 'signal_propagate USR1' SIGUSR1
  #trap 'signal_propagate USR2' SIGUSR2

  case "${NB_LOG_FILE}" in
  console | syslog)
    warn "\$NB_LOG_FILE=='${NB_LOG_FILE}' parsing is not supported, sleeping for ${NB_ENTRYPOINT_SERVICE_TIMEOUT} instead."
    warn "please consider removing the \$NB_LOG_FILE to before gathering debug bundles."
    sleep "${NB_ENTRYPOINT_SERVICE_TIMEOUT}"
    ;;
  *)
    has_logfile=1
    if test "${NB_ENTRYPOINT_TAIL_LOG_FILE}" == 1; then
      info "tailing ${NB_LOG_FILE}..."
      tail -F "${NB_LOG_FILE}" >&2 &
      pids+=("$!")
    fi

    if ! wait_for_message "${NB_ENTRYPOINT_SERVICE_TIMEOUT}" "started daemon server"; then
      warn "log line containing 'started daemon server' not found after ${NB_ENTRYPOINT_SERVICE_TIMEOUT} seconds"
      warn "daemon failed to start, exiting..."
      exit 1
    fi
    ;;
  esac

  if test "${has_logfile}" = 1 && wait_for_message "${NB_ENTRYPOINT_LOGIN_TIMEOUT}" 'peer has been successfully registered'; then
    info "already logged in, skipping 'netbird up'..."
  else
    info "logging in..."
    "${NETBIRD_BIN}" up
  fi

  wait "${SERVICE_PID}"
  signal_cleanup || true
}

main "$@"
