#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "::error::$*" >&2
    exit 1
}

if [[ ${RUNNER_ENVIRONMENT:-} != github-hosted || ${RUNNER_OS:-} != macOS || $(uname -s) != Darwin ]]; then
    fail "This test installs a system daemon and must run on a disposable GitHub macOS runner."
fi
if [[ $EUID == 0 ]]; then
    fail "Run this script as the Homebrew user, not root."
fi

readonly test_dir="${RUNNER_TEMP:?}/homebrew-cask"
readonly results_dir="$test_dir/results"
readonly app='/Applications/Netbird UI.app'
readonly plist='/Library/LaunchDaemons/netbird.plist'
readonly cask='netbirdio/tap/netbird-ui'
readonly formula='netbirdio/tap/netbird'
readonly published_cask="$test_dir/published-netbird-ui.rb"
readonly legacy_cask="$test_dir/legacy-netbird-ui.rb"
readonly rendered_cask="$test_dir/rendered-netbird-ui.rb"
readonly fixture_dir="$test_dir/fixture"
readonly serve_dir="$test_dir/serve"
readonly fixture_zip="$serve_dir/netbird-ui.zip"
readonly fixture_port=18080
readonly fixture_url="http://127.0.0.1:$fixture_port/netbird-ui.zip"
readonly marker="$test_dir/installer.marker"

mkdir -p "$results_dir" "$fixture_dir/netbird_ui_darwin" "$serve_dir" "$test_dir/downloads"
exec > >(tee "$results_dir/test.log") 2>&1

sudo -n true
if command -v netbird || [[ -e "$app" || -e "$plist" ]] || pgrep -x netbird-ui; then
    fail "The runner already has NetBird installed or running."
fi
if sudo launchctl print system/netbird > "$results_dir/initial-service.log" 2>&1; then
    fail "The runner already has a NetBird service loaded."
fi

install_attempted=false
server_pid=''
daemon_pid=''
version=''

stop_ui() {
    local status=0
    sudo pkill -x netbird-ui || status=$?
    # pkill returns 1 when the UI is already closed.
    [[ $status == 0 || $status == 1 ]]
}

cleanup() {
    local status=$?
    trap - EXIT
    set +e

    if [[ $install_attempted == true ]]; then
        stop_ui || status=1
        if [[ -S /var/run/netbird.sock ]]; then
            sudo netbird down || status=1
        fi
        if brew list --cask "$cask" >/dev/null 2>&1 || [[ -e "$app" ]]; then
            brew uninstall --cask --force "$cask" || status=1
        fi
        # A failed cask install can leave a daemon even after Homebrew rolls back the app.
        if sudo launchctl print system/netbird > "$results_dir/cleanup-service.log" 2>&1; then
            sudo netbird service stop || status=1
        fi
        if [[ -e "$plist" ]]; then
            sudo netbird service uninstall || status=1
        fi
    fi
    if [[ -f /var/log/netbird/client.log ]]; then
        sudo cat /var/log/netbird/client.log > "$results_dir/client.log" || status=1
    fi
    if command -v netbird >/dev/null; then
        brew uninstall --formula "$formula" || status=1
    fi
    if [[ -n $server_pid ]]; then
        kill "$server_pid" 2>/dev/null || true
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_logged() {
    local name=$1
    shift
    "$@" 2>&1 | tee "$results_dir/$name.log"
}

cask_field() {
    local stanza=$1 file=$2
    sed -nE "s/^[[:space:]]*$stanza \"([^\"]+)\".*/\\1/p" "$file"
}

release_fields() {
    local file=$1
    grep -E '^[[:space:]]*(version|url|sha256|app) ' "$file"
}

use_cask() {
    local file=$1
    cp "$file" "$tap_dir/Casks/netbird-ui.rb"
}

# The released installer opens the UI as root, which never returns on a headless
# runner. The cask only needs two script paths and a version argument, so the test
# ships a stub bundle that records what it received and starts the daemon.
build_fixture() {
    local bundle="$fixture_dir/netbird_ui_darwin"
    printf '#!/bin/sh\nexit 0\n' > "$bundle/netbird-ui"
    chmod 755 "$bundle/netbird-ui"
    cat > "$bundle/installer.sh" <<EOF
#!/bin/sh
set -eu
export PATH=\$PATH:/usr/local/bin:/opt/homebrew/bin
printf 'version=%s\\nuid=%s\\n' "\$1" "\$(id -u)" > '$marker'
netbird service install
netbird service start
EOF
    printf '#!/bin/sh\nexit 0\n' > "$bundle/uninstaller.sh"
    # Shipped without the executable bit so the 0755 seen after install can only come from the cask.
    chmod 644 "$bundle/installer.sh" "$bundle/uninstaller.sh"
    rm -f "$fixture_zip"
    (cd "$fixture_dir" && zip -qr "$fixture_zip" netbird_ui_darwin)
}

start_fixture_server() {
    python3 -m http.server "$fixture_port" --bind 127.0.0.1 --directory "$serve_dir" \
        > "$results_dir/fixture-server.log" 2>&1 &
    server_pid=$!
    local attempt
    for attempt in {1..20}; do
        if curl --silent --fail --output /dev/null "$fixture_url"; then
            return
        fi
        sleep 0.5
    done
    fail "The fixture HTTP server did not come up on port $fixture_port."
}

assert_published_layout() {
    local url archive script
    while read -r url; do
        archive="$test_dir/downloads/${url##*/}"
        curl --fail --location --silent --retry 3 --output "$archive" "$url"
        for script in installer.sh uninstaller.sh; do
            unzip -l "$archive" | grep -q " netbird_ui_darwin/$script\$" ||
                fail "The published archive ${url##*/} has no netbird_ui_darwin/$script."
        done
    done < <(cask_field url "$published_cask")
}

assert_no_deprecations() {
    if grep -Ei '(postflight|uninstall_preflight).*deprecated|deprecated.*(postflight|uninstall_preflight)' "$@"; then
        fail "Homebrew reported a deprecated cask lifecycle hook."
    fi
}

wait_for_daemon() {
    local attempt
    for attempt in {1..30}; do
        if sudo launchctl print system/netbird > "$results_dir/service.log" 2>&1 &&
            grep -Eq '^[[:space:]]*state = running$' "$results_dir/service.log"; then
            return
        fi
        sleep 1
    done
    cat "$results_dir/service.log"
    fail "The installed daemon did not reach the running state."
}

wait_for_exit() {
    local pid=$1 attempt
    for attempt in {1..30}; do
        if ! sudo kill -0 "$pid" 2>/dev/null; then
            return
        fi
        sleep 1
    done
    fail "Daemon process $pid is still running after removal."
}

assert_service_absent() {
    if sudo launchctl print system/netbird > "$results_dir/removed-service.log" 2>&1; then
        fail "The NetBird service is still loaded after removal."
    fi
}

assert_installed() {
    local script
    [[ -f $marker ]] || fail "The cask did not run installer.sh."
    grep -qx "version=$version" "$marker" || fail "installer.sh did not receive the cask version: $(cat "$marker")"
    grep -qx 'uid=0' "$marker" || fail "installer.sh did not run as root: $(cat "$marker")"
    [[ -d "$app" && -x "$app/netbird-ui" ]] || fail "The UI was not installed."
    for script in installer.sh uninstaller.sh; do
        [[ $(stat -f '%Lp' "$app/$script") == 755 ]] || fail "Incorrect permissions on $script."
    done
    [[ -f "$plist" ]] || fail "The installer did not create the daemon plist."
    wait_for_daemon
    daemon_pid=$(awk '/^[[:space:]]*pid = / { print $3; exit }' "$results_dir/service.log")
    [[ $daemon_pid =~ ^[0-9]+$ ]] || fail "The running daemon has no PID."
    sudo kill -0 "$daemon_pid"
}

assert_uninstalled() {
    local log=$1
    assert_no_deprecations "$log"
    [[ ! -e "$app" ]] || fail "The UI app remains after uninstall."
    [[ ! -e "$plist" ]] || fail "The daemon plist remains after uninstall."
    assert_service_absent
    wait_for_exit "$daemon_pid"
    [[ $(netbird version) == "$version" ]] || fail "Cask uninstall removed the CLI dependency."
}

installed_caskfiles() {
    local extension=$1
    find "$(brew --caskroom)/netbird-ui/.metadata" -name "netbird-ui.$extension" 2>/dev/null
}

assert_legacy_metadata() {
    installed_caskfiles rb | grep -q . || fail "The legacy cask did not leave a Ruby caskfile behind."
}

assert_steps_metadata() {
    if installed_caskfiles rb | grep -q .; then
        fail "Homebrew still keeps the legacy Ruby caskfile after reinstall."
    fi
    installed_caskfiles json | grep -q . || fail "Homebrew did not save the reinstalled cask as JSON."
}

brew --version
sw_vers
brew tap netbirdio/tap "${GITHUB_WORKSPACE:?}/.homebrew-cask-tap"
tap_dir=$(brew --repository netbirdio/tap)
readonly tap_dir

[[ -f "$tap_dir/Casks/netbird-ui.rb" ]] || fail "The tap has no Casks/netbird-ui.rb."
cp "$tap_dir/Casks/netbird-ui.rb" "$published_cask"
cp "$published_cask" "$results_dir/published-netbird-ui.rb"

version=$(brew info --json=v2 --formula "$formula" | jq -r '.formulae[0].versions.stable')
readonly version
[[ -n $version && $version != null ]] || fail "Could not read the formula version from the tap."

assert_published_layout

build_fixture
fixture_sha=$(shasum -a 256 "$fixture_zip" | cut -d' ' -f1)
readonly fixture_sha
start_fixture_server

export PROJECT=netbird-ui VERSION="$version"
export AMD="$fixture_zip" ARM="$fixture_zip" AMD_URL="$fixture_url" ARM_URL="$fixture_url"
gomplate -f "$GITHUB_WORKSPACE/client/ui/netbird-ui.rb.tmpl" -o "$rendered_cask"
cp "$rendered_cask" "$results_dir/rendered-netbird-ui.rb"

sed -E "s|^([[:space:]]*version) \"[^\"]+\"|\\1 \"$version\"|; s|^([[:space:]]*url) \"[^\"]+\"|\\1 \"$fixture_url\"|; s|^([[:space:]]*sha256) \"[^\"]+\"|\\1 \"$fixture_sha\"|" \
    "$published_cask" > "$legacy_cask"
cp "$legacy_cask" "$results_dir/legacy-netbird-ui.rb"
if ! diff <(release_fields "$legacy_cask") <(release_fields "$rendered_cask"); then
    fail "The rendered cask changes release data, not only lifecycle stanzas."
fi

use_cask "$rendered_cask"
brew info --json=v2 --cask "$cask" > "$results_dir/cask.json" 2> "$results_dir/load.log"
cat "$results_dir/load.log"
assert_no_deprecations "$results_dir/load.log"
run_logged style brew style --cask --only-cops=Cask/InstallSteps "$cask"

run_logged install-cli brew install --formula "$formula"
[[ $(netbird version) == "$version" ]] || fail "The installed CLI does not report the formula version."

for scenario in running stopped missing; do
    echo "::group::Uninstall with $scenario service"
    install_attempted=true
    sudo rm -f "$marker"
    run_logged "install-$scenario" brew install --cask "$cask"
    assert_no_deprecations "$results_dir/install-$scenario.log"
    assert_installed
    stop_ui

    case "$scenario" in
        running) ;;
        stopped)
            run_logged stop-daemon sudo netbird service stop
            wait_for_exit "$daemon_pid"
            [[ -f "$plist" ]] || fail "Stopping the daemon unexpectedly removed its plist."
            ;;
        missing)
            run_logged stop-missing-daemon sudo netbird service stop
            run_logged remove-daemon sudo netbird service uninstall
            wait_for_exit "$daemon_pid"
            [[ ! -e "$plist" ]] || fail "The missing-service scenario still has a plist."
            assert_service_absent
            ;;
        *) fail "Unknown uninstall scenario: $scenario" ;;
    esac

    run_logged "uninstall-$scenario" brew uninstall --cask "$cask"
    assert_uninstalled "$results_dir/uninstall-$scenario.log"
    echo "::endgroup::"
done

# Every existing user first meets the new cask through an upgrade of the published
# one, whose legacy flight blocks Homebrew replays from the saved Ruby caskfile.
echo "::group::Reinstall over the published legacy cask"
install_attempted=true
use_cask "$legacy_cask"
sudo rm -f "$marker"
run_logged install-legacy brew install --cask "$cask"
assert_installed
assert_legacy_metadata
stop_ui

use_cask "$rendered_cask"
sudo rm -f "$marker"
run_logged reinstall-legacy brew reinstall --cask "$cask"
assert_installed
assert_steps_metadata
stop_ui

run_logged uninstall-legacy brew uninstall --cask "$cask"
assert_uninstalled "$results_dir/uninstall-legacy.log"
echo "::endgroup::"
