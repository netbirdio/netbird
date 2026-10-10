#!/bin/bash

set -eo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/../getting-started.sh"
compose_command=$(check_docker_compose)
read -r -a compose <<< "$compose_command"

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
mkdir "$test_dir/deployment"
cd "$test_dir/deployment"

unset COMPOSE_PROJECT_NAME COMPOSE_FILE COMPOSE_ENV_FILES
# The generator's environment must not bake a project name into the output.
if [[ "${1:-}" == "--migration" ]]; then
  COMPOSE_PROJECT_NAME=render-only bash -s -- "$script_dir/../migrate.sh" >/dev/null <<'EOF'
source "$1"
INSTALL_DIR=$PWD
DOMAIN=netbird.test
generate_dashboard_env
generate_docker_compose_traefik
EOF
else
  TRAEFIK_IMAGE=traefik:v3.7.14
  NETBIRD_DOMAIN=netbird.test
  NETBIRD_AGENT_NETWORK=false
  initialize_default_values
  COMPOSE_PROJECT_NAME=render-only generate_configuration_files >/dev/null
fi

assert_network() {
  local expected="$1" actual provider
  shift
  "${compose[@]}" "$@" config --format json >config.json
  actual=$(jq -r '.networks.netbird.name' config.json)
  provider=$(jq -r '.services.traefik.command[] | select(startswith("--providers.docker.network="))' config.json)
  if [[ "$actual" != "$expected" || "$provider" != "--providers.docker.network=$expected" ]]; then
    echo "Expected network '$expected'; Compose chose '$actual', Traefik received '$provider'" >&2
    exit 1
  fi
}

assert_network deployment_netbird
COMPOSE_PROJECT_NAME=env-project assert_network env-project_netbird
echo 'COMPOSE_PROJECT_NAME=file-project' >.env
assert_network file-project_netbird
COMPOSE_PROJECT_NAME=env-project assert_network cli-project_netbird -p cli-project
: >.env
echo 'name: config-project' >>docker-compose.yml
assert_network config-project_netbird

echo "Passed 5 Compose network scoping cases."
