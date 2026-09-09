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
if ! command -v go >/dev/null 2>&1; then
  echo "go is required" >&2
  exit 127
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${IMAGE:-netbird-rootless-arbitrary-uid-test:local}"
TARGETARCH="${TARGETARCH:-$(go env GOARCH)}"
PLATFORM="${PLATFORM:-linux/${TARGETARCH}}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-30}"
TMP_DIR="$(mktemp -d)"
CONTAINER="netbird-rootless-uid-${RANDOM}-$$"
VOLUME=""

cleanup() {
  local status=$?
  "${RUNTIME}" rm -f "${CONTAINER}" >/dev/null 2>&1 || true
  if [[ -n "${VOLUME}" ]] && ! "${RUNTIME}" volume rm "${VOLUME}" >/dev/null; then
    echo "failed to remove test volume ${VOLUME}" >&2
    status=1
  fi
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
  "${RUNTIME}" run -d \
    --name "${CONTAINER}" \
    --user 1001230000:0 \
    --volume "${VOLUME}:/var/lib/netbird" \
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
    test -r /usr/local/bin/netbird-entrypoint.sh
    test -x /usr/local/bin/netbird-entrypoint.sh
    test "$(head -n 1 /usr/local/bin/netbird-entrypoint.sh)" = "#!/usr/bin/env bash"
    bash -n /usr/local/bin/netbird-entrypoint.sh
    touch /var/lib/netbird/.uid-smoke
    rm /var/lib/netbird/.uid-smoke
    test -S /var/lib/netbird/netbird.sock
    test "$(stat -c %a /var/lib/netbird/config.json)" = 600
    test "$(stat -c %a /var/lib/netbird/active_profile.json)" = 600
  '
  "${RUNTIME}" exec "${CONTAINER}" \
    /usr/local/bin/netbird profile list >/dev/null
}

assert_same_uid_restart() {
  echo "==> Verifying persistent profiles with the same runtime UID"
  local profile_name="rootless-restart" profiles_before profiles_after

  "${RUNTIME}" exec "${CONTAINER}" \
    /usr/local/bin/netbird profile add "${profile_name}" >/dev/null
  profiles_before="$("${RUNTIME}" exec "${CONTAINER}" \
    /usr/local/bin/netbird profile list --show-id)"
  if [[ "${profiles_before}" != *"${profile_name}"* ]]; then
    echo "created profile is missing before restart" >&2
    return 1
  fi

  "${RUNTIME}" stop "${CONTAINER}" >/dev/null
  "${RUNTIME}" rm "${CONTAINER}" >/dev/null
  start_container
  wait_until_live
  assert_arbitrary_uid_contract

  profiles_after="$("${RUNTIME}" exec "${CONTAINER}" \
    /usr/local/bin/netbird profile list --show-id)"
  if [[ "${profiles_after}" != "${profiles_before}" ]]; then
    echo "profiles changed after recreating the container with the same volume and UID" >&2
    container_logs
    return 1
  fi

  "${RUNTIME}" exec "${CONTAINER}" \
    /usr/local/bin/netbird profile rename "${profile_name}" "${profile_name}-renamed" >/dev/null
  profiles_after="$("${RUNTIME}" exec "${CONTAINER}" \
    /usr/local/bin/netbird profile list --show-id)"
  if [[ "${profiles_after}" != *"${profile_name}-renamed"* ]]; then
    echo "persisted profile could not be updated after restart" >&2
    return 1
  fi
}

build_image
VOLUME="$("${RUNTIME}" volume create "${CONTAINER}-state")"
start_container
wait_until_live
assert_arbitrary_uid_contract
assert_same_uid_restart

echo "==> Rootless arbitrary UID and same-UID persistence validation passed"
