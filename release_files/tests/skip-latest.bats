#!/usr/bin/env bats
#
# Tests for release_files/skip-latest.sh -- the SKIP_LATEST decision that keeps
# a patch on an older release line from moving the "latest" pointers.
#
# Run with:  bats release_files/tests/

# The sh -c scripts below take their paths as $1 and $2 rather than having
# them spliced in, where an apostrophe in a path would break the quoting.
# shellcheck disable=SC2016 # so $1 in single quotes is meant for sh

setup() {
  # First, before anything can fail: teardown removes $tmp, and a tmp
  # exported by the caller must never be what it finds there.
  tmp=''
  SCRIPT="${BATS_TEST_DIRNAME}/../skip-latest.sh"

  # Some tests build a repository of their own. Git honours GIT_DIR and its
  # kin over the current directory, and sets them for hooks, so a run from a
  # hook would commit and tag in the caller's repository instead -- and still
  # pass, reading back what it wrote. Clear every variable that ties git to a
  # repository; git lists them itself.
  # shellcheck disable=SC2046 # one name per word is the point
  unset $(git rev-parse --local-env-vars)
  # Neutralise the developer's git config too: a global tag.gpgSign turns
  # `git tag <name>` into an annotated tag and fails for want of a message.
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

  # A tag set with a newer line released and an older one still maintained.
  TAGS='v0.79.0
v0.80.0-rc.1
v0.80.0
v0.80.1
v0.81.0-rc.1
v0.81.0-rc.2
v0.81.0'
}

teardown() {
  if [[ -n "${tmp:-}" ]]; then rm -rf "$tmp"; fi
}

# decide <tag> [tags]  -- tags default to $TAGS
decide() {
  local tag=$1
  local tags=${2-$TAGS}
  SKIP_LATEST_TAGS="$tags" run "$SCRIPT" "$tag"
}

# make_repo <tag>...  -- a repository of the test's own at $repo, holding the
# given tags; teardown removes it.
make_repo() {
  tmp=$(mktemp -d)
  repo="$tmp/repo"
  mkdir -p "$repo"
  # No `|| ...` after this subshell: it would switch off bats' set -e inside,
  # and a failed cd or git init would let the commit and tags land in
  # whatever repository encloses the current directory.
  (
    cd "$repo" || exit
    # An empty --template copies no hooks into the repository, whatever
    # GIT_TEMPLATE_DIR the caller has; init.templateDir is already off.
    git init -q --template= .
    git -c user.email=t@example.com -c user.name=t commit -q --allow-empty -m init
    for tag in "$@"; do git tag "$tag"; done
  )
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

@test "a tag missing from the list is refused, not decided" {
  # An empty ls-remote or a checkout without tags must not move latest.
  decide v0.82.0
  [ "$status" -eq 1 ]
  [ "${lines[-1]}" != "false" ]
}

@test "an empty SKIP_LATEST_TAGS is an empty list, not ask git" {
  # Guards the ${VAR+set} test: a plain -n check would fall through to git
  # and find v0.80.0 there, letting the script succeed. The tag lives in a
  # repository made here, not this one: CI checks this one out without tags,
  # where git would find nothing either and the test could not tell.
  make_repo v0.80.0
  SKIP_LATEST_TAGS='' run sh -c 'cd "$1" && "$2" v0.80.0 </dev/null' sh "$repo" "$SCRIPT"
  [ "$status" -eq 1 ]
}

@test "falls back to git tag when SKIP_LATEST_TAGS is unset" {
  # The CI path.
  make_repo v0.80.1 v0.81.0 v0.80.2
  run env -u SKIP_LATEST_TAGS sh -c 'cd "$1" && "$2" v0.80.2 </dev/null' sh "$repo" "$SCRIPT"
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = "true" ]
}

@test "missing argument is a usage error" {
  SKIP_LATEST_TAGS='' run "$SCRIPT"
  [ "$status" -eq 2 ]
}

@test "the decision goes to stdout and the reasoning to stderr" {
  SKIP_LATEST_TAGS='v0.81.0' run sh -c '"$1" v0.81.0 2>/dev/null' sh "$SCRIPT"
  [ "$status" -eq 0 ]
  [ "$output" = "false" ]
}
