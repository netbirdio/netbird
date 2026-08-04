#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT

source_without_main() {
  local source_file=$1
  local destination_file=$2
  local entrypoint_count
  entrypoint_count=$(awk '/^[[:space:]]*init_environment[[:space:]]*$/ { count++ } END { print count + 0 }' "$source_file")
  require_equal "$source_file entrypoint count" 1 "$entrypoint_count"
  awk '!/^[[:space:]]*init_environment[[:space:]]*$/' "$source_file" > "$destination_file"
  # shellcheck disable=SC1090
  source "$destination_file"
}

decoded_key_length() {
  printf '%s' "$1" | openssl base64 -d -A | wc -c | tr -d '[:space:]'
}

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

yaml_section_value() {
  local section=$1
  local key=$2
  local file=$3
  sed -n "/^  ${section}:$/,/^  [[:alnum:]_].*:$/p" "$file" |
    sed -n "s/^    ${key}: \"\\(.*\\)\"/\\1/p"
}

require_nonempty() {
  local description=$1
  local value=$2
  if [[ -z "$value" ]]; then
    echo "$description is empty" >&2
    return 1
  fi
}

require_equal() {
  local description=$1
  local expected=$2
  local actual=$3
  if [[ "$actual" != "$expected" ]]; then
    echo "$description: expected $expected, got $actual" >&2
    return 1
  fi
}

require_distinct() {
  local description=$1
  local first=$2
  local second=$3
  if [[ "$first" == "$second" ]]; then
    echo "$description must differ" >&2
    return 1
  fi
}

test_community_installer() (
  umask 022
  mkdir -p "$test_root/community"
  source_without_main \
    "$repo_root/infrastructure_files/getting-started.sh" \
    "$test_root/community-installer.sh"
  set +u

  initialize_default_values
  NETBIRD_DOMAIN=netbird.test.example
  NETBIRD_HTTP_PROTOCOL=https
  NETBIRD_PORT=443
  REVERSE_PROXY_TYPE=5
  BIND_LOCALHOST_ONLY=true
  EXTERNAL_PROXY_NETWORK=""
  TRAEFIK_IP=172.30.0.10

  cd "$test_root/community"
  generate_configuration_files

  session_key=$(yaml_section_value auth sessionCookieEncryptionKey config.yaml)
  datastore_key=$(yaml_section_value store encryptionKey config.yaml)

  require_nonempty "community session cookie key" "$session_key"
  require_equal "community decoded key length" 32 "$(decoded_key_length "$session_key")"
  require_nonempty "community datastore key" "$datastore_key"
  require_equal "community decoded datastore key length" 32 "$(decoded_key_length "$datastore_key")"
  require_distinct "community session and datastore keys" "$session_key" "$datastore_key"
  require_equal "community config mode" 600 "$(file_mode config.yaml)"
)

test_enterprise_installer() (
  mkdir -p "$test_root/enterprise"
  source_without_main \
    "$repo_root/infrastructure_files/getting-started-enterprise.sh" \
    "$test_root/enterprise-installer.sh"
  set +u

  check_openssl() { :; }
  check_docker_compose() { printf '%s\n' true; }
  require_eula_acceptance() { :; }
  read_yes_no() { printf '%s\n' no; }
  read_nb_domain() { printf '%s\n' netbird.test.example; }
  read_secret() { printf '%s\n' test-license; }
  wait_postgres() { :; }
  sleep() { :; }

  cd "$test_root/enterprise"
  init_environment >/dev/null

  session_key=$(yaml_section_value auth sessionCookieEncryptionKey config.yaml)
  datastore_key=$(yaml_section_value store encryptionKey config.yaml)

  require_nonempty "enterprise session cookie key" "$session_key"
  require_equal "enterprise decoded key length" 32 "$(decoded_key_length "$session_key")"
  require_nonempty "enterprise datastore key" "$datastore_key"
  require_equal "enterprise decoded datastore key length" 32 "$(decoded_key_length "$datastore_key")"
  require_distinct "enterprise session and datastore keys" "$session_key" "$datastore_key"
  require_equal "enterprise config mode" 600 "$(file_mode config.yaml)"
)

case "${1:-all}" in
  community)
    test_community_installer
    ;;
  enterprise)
    test_enterprise_installer
    ;;
  all)
    test_community_installer
    test_enterprise_installer
    ;;
  *)
    echo "usage: $0 [community|enterprise|all]" >&2
    exit 2
    ;;
esac
