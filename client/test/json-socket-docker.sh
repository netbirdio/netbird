#!/usr/bin/env bash
set -eEuo pipefail

usage() {
  cat <<'EOF'
Usage: client/test/json-socket-docker.sh [tcp|unix|both]

Builds the NetBird client Docker image from the local source tree, starts
`netbird service run` in a container with --enable-json-socket, and verifies
that the HTTP/JSON daemon gateway responds to Status requests.

Modes:
  tcp   Validate tcp://0.0.0.0:8080 via a published localhost port (default)
  unix  Validate unix:///sock/netbird-http.sock via a bind-mounted socket dir
  both  Run both validations

Environment:
  CONTAINER_RUNTIME  docker or podman. Auto-detected if unset.
  IMAGE              Image tag to build. Default: netbird-json-socket-test:local
  TARGETARCH         Go/Docker target arch. Default: `go env GOARCH`
  PLATFORM           Docker platform. Default: linux/$TARGETARCH
  WAIT_TIMEOUT       Seconds to wait for the JSON socket. Default: 30
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

MODE="${1:-tcp}"
case "${MODE}" in
  tcp|unix|both) ;;
  *)
    usage >&2
    echo "invalid mode: ${MODE}" >&2
    exit 2
    ;;
esac

RUNTIME="${CONTAINER_RUNTIME:-}"
if [[ -z "${RUNTIME}" ]]; then
  if command -v docker >/dev/null 2>&1; then
    RUNTIME=docker
  elif command -v podman >/dev/null 2>&1; then
    RUNTIME=podman
  else
    echo "docker or podman is required" >&2
    exit 127
  fi
fi
if ! command -v "${RUNTIME}" >/dev/null 2>&1; then
  echo "container runtime not found: ${RUNTIME}" >&2
  exit 127
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 127
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${IMAGE:-netbird-json-socket-test:local}"
TARGETARCH="${TARGETARCH:-$(go env GOARCH)}"
PLATFORM="${PLATFORM:-linux/${TARGETARCH}}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-30}"
TMP_DIR="$(mktemp -d)"
CONTAINERS=()

cleanup() {
  local status=$?
  for container in "${CONTAINERS[@]:-}"; do
    "${RUNTIME}" rm -f "${container}" >/dev/null 2>&1 || true
  done
  rm -rf "${TMP_DIR}"
  exit "${status}"
}
trap cleanup EXIT

build_image() {
  echo "==> Building Linux ${TARGETARCH} netbird binary"
  mkdir -p "${TMP_DIR}/context/client"
  cp "${ROOT_DIR}/client/Dockerfile" "${TMP_DIR}/context/Dockerfile"
  cp "${ROOT_DIR}/client/netbird-entrypoint.sh" "${TMP_DIR}/context/client/netbird-entrypoint.sh"

  (cd "${ROOT_DIR}" && CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" go build -o "${TMP_DIR}/context/netbird" ./client)

  echo "==> Building ${IMAGE} for ${PLATFORM}"
  "${RUNTIME}" build \
    --platform "${PLATFORM}" \
    --build-arg NETBIRD_BINARY=netbird \
    -t "${IMAGE}" \
    -f "${TMP_DIR}/context/Dockerfile" \
    "${TMP_DIR}/context"
}

pick_port() {
  python3 - <<'PY'
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

assert_status_json() {
  local response_file="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "${response_file}" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
if not data.get("status"):
    raise SystemExit("missing non-empty status field")
if "daemonVersion" not in data:
    raise SystemExit("missing daemonVersion field")
print(f"status={data['status']} daemonVersion={data['daemonVersion']}")
PY
  else
    grep -q '"status"' "${response_file}"
    grep -q '"daemonVersion"' "${response_file}"
    cat "${response_file}"
  fi
}

container_logs() {
  local container="$1"
  echo "---- ${container} logs ----" >&2
  "${RUNTIME}" logs "${container}" >&2 || true
  echo "--------------------------" >&2
}

wait_for_http_status() {
  local container="$1"
  local response="${TMP_DIR}/${container}.json"
  local curl_err="${TMP_DIR}/${container}.curl.err"
  shift
  local deadline=$((SECONDS + WAIT_TIMEOUT))

  while (( SECONDS < deadline )); do
    if curl -fsS "$@" \
      -X POST \
      -H 'Content-Type: application/json' \
      -d '{}' \
      -o "${response}" \
      2>"${curl_err}"; then
      assert_status_json "${response}"
      return 0
    fi

    if ! "${RUNTIME}" ps --format '{{.Names}}' | grep -Fxq "${container}"; then
      echo "container exited before JSON socket became ready" >&2
      container_logs "${container}"
      return 1
    fi
    sleep 1
  done

  echo "timed out waiting for JSON socket after ${WAIT_TIMEOUT}s" >&2
  cat "${curl_err}" >&2 || true
  container_logs "${container}"
  return 1
}

run_netbird_container() {
  local container="$1"
  local json_socket="$2"
  shift 2

  CONTAINERS+=("${container}")
  "${RUNTIME}" run --rm -d \
    --name "${container}" \
    -e NB_STATE_DIR=/tmp/netbird-state \
    --entrypoint /usr/local/bin/netbird \
    "$@" \
    "${IMAGE}" \
    --log-file console \
    --daemon-addr unix:///tmp/netbird.sock \
    service run \
    --enable-json-socket \
    --json-socket "${json_socket}" >/dev/null
}

run_tcp_test() {
  local port container
  port="$(pick_port)"
  container="nb-json-socket-tcp-$RANDOM-$RANDOM"

  echo "==> Validating TCP JSON socket on 127.0.0.1:${port}"
  run_netbird_container "${container}" "tcp://0.0.0.0:8080" -p "127.0.0.1:${port}:8080"
  wait_for_http_status "${container}" "http://127.0.0.1:${port}/daemon.DaemonService/Status"
}

run_unix_test() {
  local sock_dir sock_path container
  sock_dir="${TMP_DIR}/sock"
  sock_path="${sock_dir}/netbird-http.sock"
  container="nb-json-socket-unix-$RANDOM-$RANDOM"
  mkdir -p "${sock_dir}"

  echo "==> Validating Unix JSON socket at ${sock_path}"
  run_netbird_container "${container}" "unix:///sock/netbird-http.sock" -v "${sock_dir}:/sock"
  wait_for_http_status "${container}" --unix-socket "${sock_path}" "http://unix/daemon.DaemonService/Status"
}

build_image

case "${MODE}" in
  tcp)
    run_tcp_test
    ;;
  unix)
    run_unix_test
    ;;
  both)
    run_tcp_test
    run_unix_test
    ;;
esac

echo "==> Docker JSON socket validation passed (${MODE})"
