#!/usr/bin/env bash
# Runs the NetBird daemon and brings the connection up in one container process.
#
# A thin wrapper is needed (rather than a one-line ENTRYPOINT) for two reasons:
#   1. Two processes must run: the daemon (`service run`, long-lived) and a
#      one-shot `up` that brings the connection up.
#   2. Signal handling: as PID 1 the wrapper must forward SIGTERM/SIGINT to the
#      daemon so it tears down WireGuard and deregisters ephemeral peers on
#      `docker stop`. Without this the daemon would be killed uncleanly.
#
# `netbird up` waits for the daemon to become ready on its own, so no readiness
# poll is needed here.
set -eEuo pipefail

NETBIRD_BIN="${NETBIRD_BIN:-"netbird"}"
export NB_LOG_FILE="${NB_LOG_FILE:-"console,/var/log/netbird/client.log"}"

daemon=""
cleanup() { [[ -n "${daemon}" ]] && kill -TERM "${daemon}" 2>/dev/null || true; }
trap cleanup SIGTERM SIGINT EXIT

"${NETBIRD_BIN}" service run &
daemon=$!

"${NETBIRD_BIN}" up

wait "${daemon}"
