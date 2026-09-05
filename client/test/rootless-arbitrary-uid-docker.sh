#!/usr/bin/env bash
set -eEuo pipefail

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

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${IMAGE:-netbird-rootless-arbitrary-uid-test:local}"
TARGETARCH="${TARGETARCH:-$(go env GOARCH)}"
PLATFORM="${PLATFORM:-linux/${TARGETARCH}}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-30}"
TMP_DIR="$(mktemp -d)"
CONTAINER="netbird-rootless-uid-${RANDOM}-$$"

cleanup() {
  local status=$?
  "${RUNTIME}" rm -f "${CONTAINER}" >/dev/null 2>&1 || true
  rm -rf "${TMP_DIR}"
  exit "${status}"
}
trap cleanup EXIT

container_logs() {
  echo "---- ${CONTAINER} logs ----" >&2
  "${RUNTIME}" logs "${CONTAINER}" >&2 || true
  echo "----------------------------" >&2
}

build_image() {
  echo "==> Building Linux ${TARGETARCH} netbird binary"
  mkdir -p "${TMP_DIR}/context/client"
  cp "${ROOT_DIR}/client/Dockerfile-rootless" "${TMP_DIR}/context/Dockerfile"
  cp "${ROOT_DIR}/client/netbird-entrypoint.sh" "${TMP_DIR}/context/client/netbird-entrypoint.sh"

  (
    cd "${ROOT_DIR}"
    CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" \
      go build -o "${TMP_DIR}/context/netbird" ./client
  )

  echo "==> Building ${IMAGE} for ${PLATFORM}"
  "${RUNTIME}" build \
    --platform "${PLATFORM}" \
    --build-arg NETBIRD_BINARY=netbird \
    -t "${IMAGE}" \
    -f "${TMP_DIR}/context/Dockerfile" \
    "${TMP_DIR}/context"
}

start_container() {
  echo "==> Starting ${CONTAINER} as unmapped UID 1001230000"
  "${RUNTIME}" run --rm -d \
    --name "${CONTAINER}" \
    --user 1001230000:0 \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --entrypoint /usr/local/bin/netbird \
    "${IMAGE}" \
    --log-file console \
    service run >/dev/null
}

wait_until_live() {
  local deadline=$((SECONDS + WAIT_TIMEOUT))

  while (( SECONDS < deadline )); do
    if "${RUNTIME}" exec "${CONTAINER}" \
      /usr/local/bin/netbird status --check live >/dev/null 2>&1; then
      return 0
    fi

    if [[ "$("${RUNTIME}" inspect -f '{{.State.Running}}' "${CONTAINER}" 2>/dev/null || true)" != "true" ]]; then
      echo "container exited before the daemon became live" >&2
      container_logs
      return 1
    fi
    sleep 1
  done

  echo "timed out waiting for the daemon after ${WAIT_TIMEOUT}s" >&2
  container_logs
  return 1
}

assert_arbitrary_uid_contract() {
  echo "==> Verifying arbitrary UID image contract"
  "${RUNTIME}" exec "${CONTAINER}" sh -ec '
    test "$(id -u)" = 1001230000
    test "$(id -g)" = 0
    test "${HOME}" = /var/lib/netbird
    touch /var/lib/netbird/.uid-smoke
    rm /var/lib/netbird/.uid-smoke
    test -S /var/lib/netbird/netbird.sock
  '
  "${RUNTIME}" exec "${CONTAINER}" \
    /usr/local/bin/netbird profile list >/dev/null
}

build_image
start_container
wait_until_live
assert_arbitrary_uid_contract

echo "==> Rootless arbitrary UID validation passed"
