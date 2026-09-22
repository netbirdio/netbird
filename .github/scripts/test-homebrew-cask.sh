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
readonly rendered_cask="$test_dir/rendered-netbird-ui.rb"

mkdir -p "$results_dir" "$test_dir/downloads"
exec > >(tee "$results_dir/test.log") 2>&1

sudo -n true
if command -v netbird || [[ -e "$app" || -e "$plist" ]] || pgrep -x netbird-ui; then
    fail "The runner already has NetBird installed or running."
fi
if sudo launchctl print system/netbird > "$results_dir/initial-service.log" 2>&1; then
    fail "The runner already has a NetBird service loaded."
fi

install_attempted=false
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
    sed -nE "s/^[[:space:]]*$1 \"([^\"]+)\".*/\\1/p" "$2"
}

release_fields() {
    grep -E '^[[:space:]]*(version|url|sha256|app) ' "$1"
}

use_cask() {
    cp "$1" "$tap_dir/Casks/netbird-ui.rb"
}

assert_no_deprecations() {
    if grep -Ei '(postflight|uninstall_preflight).*deprecated|deprecated.*(postflight|uninstall_preflight)' "$@"; then
        fail "Homebrew reported a deprecated cask lifecycle hook."
    fi
}

assert_no_launchctl_noise() {
    if grep -E 'Boot-out failed|Unload failed' "$@"; then
        fail "The uninstall printed launchctl errors that the legacy stanza kept silent."
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
    local log=$1 script
    if grep -F 'Netbird UI Version:' "$log"; then
        fail "The installer did not receive the expected version argument."
    fi
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
    assert_no_launchctl_noise "$log"
    [[ ! -e "$app" ]] || fail "The UI app remains after uninstall."
    [[ ! -e "$plist" ]] || fail "The daemon plist remains after uninstall."
    assert_service_absent
    wait_for_exit "$daemon_pid"
    [[ $(netbird version) == "$version" ]] || fail "Cask uninstall removed the CLI dependency."
}

installed_caskfiles() {
    find "$(brew --caskroom)/netbird-ui/.metadata" -name "netbird-ui.$1" 2>/dev/null
}

assert_legacy_metadata() {
    installed_caskfiles rb | grep -q . || fail "The published cask did not leave a legacy Ruby caskfile behind."
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

# The tap's published cask is the fixture: it names the signed archives that real
# users install today, and it carries their checksums. Changes to the installer
# scripts inside those archives need freshly packaged artifacts instead.
[[ -f "$tap_dir/Casks/netbird-ui.rb" ]] || fail "The tap has no Casks/netbird-ui.rb."
cp "$tap_dir/Casks/netbird-ui.rb" "$published_cask"
cp "$published_cask" "$results_dir/published-netbird-ui.rb"

version=$(cask_field version "$published_cask")
readonly version
[[ -n $version ]] || fail "The published cask has no version stanza."
[[ $(cask_field url "$published_cask" | wc -l) -eq 2 ]] || fail "Expected exactly two url stanzas in the published cask."
[[ $(cask_field sha256 "$published_cask" | wc -l) -eq 2 ]] || fail "Expected exactly two sha256 stanzas in the published cask."

amd_url='' amd_sha='' arm_url='' arm_sha=''
while IFS=$'\t' read -r url sum; do
    [[ $url == *"$version"* ]] || fail "Download URL does not carry the cask version: $url"
    case "$url" in
        *_darwin_amd64_*) amd_url=$url; amd_sha=$sum ;;
        *_darwin_arm64_*) arm_url=$url; arm_sha=$sum ;;
        *) fail "Unrecognised download URL in the published cask: $url" ;;
    esac
done < <(paste <(cask_field url "$published_cask") <(cask_field sha256 "$published_cask"))
[[ -n $amd_url && -n $amd_sha && -n $arm_url && -n $arm_sha ]] || fail "Could not read both architectures from the published cask."

formula_version=$(brew info --json=v2 --formula "$formula" | jq -r '.formulae[0].versions.stable')
if [[ $formula_version != "$version" ]]; then
    fail "The tap is mid-release: formula $formula_version, cask $version. Retry once both match."
fi

export PROJECT=netbird-ui VERSION="$version" AMD_URL="$amd_url" ARM_URL="$arm_url"
export AMD="$test_dir/downloads/${amd_url##*/}" ARM="$test_dir/downloads/${arm_url##*/}"
curl --fail --location --retry 3 --output "$AMD" "$AMD_URL"
curl --fail --location --retry 3 --output "$ARM" "$ARM_URL"
shasum -a 256 --check <<EOF
$amd_sha  $AMD
$arm_sha  $ARM
EOF

gomplate -f "$GITHUB_WORKSPACE/client/ui/netbird-ui.rb.tmpl" -o "$rendered_cask"
cp "$rendered_cask" "$results_dir/rendered-netbird-ui.rb"
if ! diff <(release_fields "$published_cask") <(release_fields "$rendered_cask"); then
    fail "The rendered cask changes release data, not only lifecycle stanzas."
fi

use_cask "$rendered_cask"
brew info --json=v2 --cask "$cask" > "$results_dir/cask.json" 2> "$results_dir/load.log"
cat "$results_dir/load.log"
assert_no_deprecations "$results_dir/load.log"
run_logged style brew style --cask --only-cops=Cask/InstallSteps "$cask"

run_logged install-cli brew install --formula "$formula"
[[ $(netbird version) == "$version" ]] || fail "The CLI fixture version does not match the UI."

for scenario in running stopped missing; do
    echo "::group::Uninstall with $scenario service"
    install_attempted=true
    run_logged "install-$scenario" brew install --cask "$cask"
    assert_no_deprecations "$results_dir/install-$scenario.log"
    assert_installed "$results_dir/install-$scenario.log"
    stop_ui

    case "$scenario" in
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
    esac

    run_logged "uninstall-$scenario" brew uninstall --cask "$cask"
    assert_uninstalled "$results_dir/uninstall-$scenario.log"
    echo "::endgroup::"
done

# Every existing user first meets the new cask through an upgrade of the published
# one, whose legacy flight blocks Homebrew replays from the saved Ruby caskfile.
echo "::group::Reinstall over the published legacy cask"
install_attempted=true
use_cask "$published_cask"
run_logged install-legacy brew install --cask "$cask"
assert_installed "$results_dir/install-legacy.log"
assert_legacy_metadata
stop_ui

use_cask "$rendered_cask"
run_logged reinstall-legacy brew reinstall --cask "$cask"
assert_installed "$results_dir/reinstall-legacy.log"
assert_steps_metadata
stop_ui

run_logged uninstall-legacy brew uninstall --cask "$cask"
assert_uninstalled "$results_dir/uninstall-legacy.log"
echo "::endgroup::"
