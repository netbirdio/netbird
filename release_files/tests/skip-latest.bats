#!/usr/bin/env bats
#
# Tests for release_files/skip-latest.sh -- the SKIP_LATEST decision that keeps
# a patch on an older release line from moving the "latest" pointers.
#
# Run with:  bats release_files/tests/

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../skip-latest.sh"

  # A tag set with a newer line released and an older one still maintained.
  TAGS='v0.79.0
v0.80.0-rc.1
v0.80.0
v0.80.1
v0.81.0-rc.1
v0.81.0-rc.2
v0.81.0'
}

# decide <tag> [tags]  -- tags default to $TAGS
decide() {
  local tag=$1
  local tags=${2-$TAGS}
  SKIP_LATEST_TAGS="$tags" run "$SCRIPT" "$tag"
}

@test "the newest release moves latest" {
  decide v0.81.0
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "false" ]
}

@test "a patch on the newest line moves latest" {
  decide v0.81.1 "$TAGS
v0.81.1"
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "false" ]
}

@test "a patch on an older line does not drag latest backwards" {
  decide v0.80.2 "$TAGS
v0.80.2"
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "true" ]
}

@test "a release candidate never moves latest" {
  decide v0.82.0-rc.1 "$TAGS
v0.82.0-rc.1"
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "true" ]
}

@test "a release is not held back by its own release candidate" {
  # sort -V orders 0.81.0-rc.1 after 0.81.0.
  decide v0.81.0 'v0.81.0-rc.1
v0.81.0'
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "false" ]
}

@test "canary and hotfix tags cannot skew the comparison" {
  decide v0.81.0 "$TAGS
v0.99.0-canary.pr-1234.1
v0.99.0-hotfix-1"
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "false" ]
}

@test "a new minor moves latest" {
  decide v0.82.0 "$TAGS
v0.82.0"
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "false" ]
}

@test "version ordering is numeric, not lexicographic" {
  decide v0.9.0 'v0.9.0
v0.10.0'
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "true" ]
}

@test "double-digit patch sorts above single-digit" {
  decide v0.81.10 'v0.81.9
v0.81.10'
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "false" ]
}

@test "first release moves latest when only prereleases exist" {
  decide v0.1.0 'v0.1.0-rc.1
v0.1.0'
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "false" ]
}

@test "an empty SKIP_LATEST_TAGS means no tags, not ask git" {
  # Guards the ${VAR+set} test: a plain -n check would fall through to git and
  # silently read this repository's real tags.
  decide v0.1.0 ''
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "false" ]
}

@test "falls back to git tag when SKIP_LATEST_TAGS is unset" {
  # The CI path.
  tmp=$(mktemp -d)
  repo="$tmp/repo"
  mkdir -p "$repo"
  # Neutralise the developer's git config: a global tag.gpgSign turns
  # `git tag <name>` into an annotated tag and fails for want of a message.
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
  (
    cd "$repo"
    git init -q .
    git -c user.email=t@example.com -c user.name=t commit -q --allow-empty -m init
    git tag v0.80.1
    git tag v0.81.0
    git tag v0.80.2
  ) || return 1
  run env -u SKIP_LATEST_TAGS sh -c "cd '$repo' && '$SCRIPT' v0.80.2 </dev/null"
  rm -rf "$tmp"
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "true" ]
}

@test "missing argument is a usage error" {
  SKIP_LATEST_TAGS='' run "$SCRIPT"
  [ "$status" -eq 2 ]
}

@test "the decision goes to stdout and the reasoning to stderr" {
  SKIP_LATEST_TAGS='v0.81.0' run sh -c "'$SCRIPT' v0.81.0 2>/dev/null"
  [ "$status" -eq 0 ]
  [ "$output" = "false" ]
}
