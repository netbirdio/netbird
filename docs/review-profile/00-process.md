# 00 Process: PR hygiene and CI gates

These rules apply before any line of code is read. Most are mechanical and
mirror a CI check, so the agent's job is to say early what CI will say late,
with the fix attached.

## Title and description

### PROC-001 PR title starts with an allowed bracketed tag
severity: blocker
scope: PR title
check: title matches `^\[([a-z,]+)\]\s+.+` and every comma-separated tag is in
the `allowedTags` array of
[`.github/workflows/pr-title-check.yml`](../../.github/workflows/pr-title-check.yml).
Read the array from the file at review time; at the time of writing it is
`management, client, android, ios, signal, proxy, relay, misc, infrastructure,
self-hosted, doc`.
say: "PR Title Check will fail: the tag must be one of <list from the workflow>,
e.g. `[client] <subject>`."
why: `pr-title-check.yml` runs on every title edit. Multiple tags are
comma-separated inside one pair of brackets. The tag must match the component
changed in the diff, not the component the author reads most.

### PROC-002 Tag matches the paths in the diff
severity: should
scope: PR title vs changed files
check: map changed paths to components (`client/` and `route/`, `dns/`,
`sharedsock/`, `util/` used only by the client -> `client`; `management/` ->
`management`; `signal/`, `relay/`, `proxy/` -> same name; `client/android` ->
`android`; `client/ios` -> `ios`; `infrastructure_files/`, `.github/`,
`release_files/`, `.goreleaser*` -> `infrastructure` or `self-hosted`;
docs-only -> `doc`; anything else -> `misc`). Flag a tag that names no changed
component or a changed component with no tag.
say: "The diff changes `<component>` but the title tags `<tag>`; use
`[<a>,<b>]`."
why: release notes and the review routing are built from the tag.

### PROC-003 The template is filled, not replaced
severity: should
scope: PR body
check: body contains the headings of
[`.github/pull_request_template.md`](../../.github/pull_request_template.md):
"Describe your changes", "Issue ticket number and link", the checklist, the
"Documentation" section with exactly one of the two boxes ticked, and the docs
PR URL when "added/updated documentation" is ticked. Flag an unticked
checklist for a behaviour change, and a body that deleted the Documentation
section.
say: "The Docs Acknowledgement check reads the Documentation section; keep the
template and tick exactly one box (and paste the docs PR when docs were
added)."
why: `docs-ack.yml` fails when neither or both documentation boxes are ticked,
and when "added" is ticked without a `https://github.com/netbirdio/docs/pull/`
URL. Dependabot is the only exempt author.

### PROC-004 Behaviour change links an agreed ticket
severity: ask
scope: PR body, diff
check: the diff touches a high-risk area (public API or OpenAPI, protos,
behaviour existing deployments notice, peer connectivity, routing, firewall,
DNS, interface, auth, CLI or service flags, config format, daemon IPC, store
schema or migration, or a new feature) and the body links no issue under
"Issue ticket number and link".
say: "This changes <area>, which CONTRIBUTING.md lists as needing an agreed
issue first. Which discussion or issue is this for?"
why: CONTRIBUTING.md "Ticket first, PR second" and "High-risk areas". A PR
without a ticket may be closed on arrival; the agent asks rather than closes.

### PROC-005 Description is short and leads with why
severity: nit
scope: PR body
check: body (outside the template text) exceeds roughly 1000 words, or is a
bullet list of files changed, or a per-function walkthrough, or ends with a
summary section.
say: "Reviewers read the diff; keep the description to the problem, the reason
for this approach, and what the diff cannot say for itself."
why: AGENTS.md "Commits, PRs, releases". Long descriptions are the most common
tell of an unreviewed AI-drafted PR.

### PROC-006 No attribution trailers anywhere
severity: blocker
scope: commit messages, PR body
check: any line matching `^[^[:alnum:]]*(co-authored-by|claude-session|generated-by):`
(any case), or a "Generated with/by <Tool>" footer, in any commit on the branch
or in the PR body. The exact patterns are in
[`.githooks/commit-msg`](../../.githooks/commit-msg).
say: "Attribution trailers are refused here (AGENTS.md, commit-msg hook,
CodeRabbit pre-merge check). Remove `<line>` from <commit or body>."
why: contributors own their contributions. The hook refuses the commit locally
and `.coderabbit.yaml` has a pre-merge check that fails the PR.

### PROC-007 Commit subjects use the same `[scope] Subject` form
severity: nit
scope: commit messages
check: a commit subject without a leading bracketed tag, or with a bullet list
of files in the body. Squash-merge makes this cosmetic, so never block on it.
say: "Commit subjects follow `[scope] Subject`; the PR is squashed so this is
only for the branch history."

## Size and purpose

### PROC-010 One PR, one purpose
severity: should
scope: diff
check: the diff mixes a refactor with a fix, or a fix with a feature, or
reformats files it does not otherwise change. A reliable tell: files changed
that no commit message mentions, or renames alongside logic changes.
say: "Split the <refactor/rename> from the <fix>; each should build and make
sense alone. The PR template's single-purpose box is part of the contract."
why: AGENTS.md "One PR, one purpose"; PR template checklist.

### PROC-011 Size is reviewable
severity: ask
scope: diff
check: hand-written changes (exclude `*.pb.go`, `*.gen.go`, `go.sum`,
`bundle.yaml`, lockfiles, fixtures under `testdata/`, vendored and frontend
`dist`) exceed about 400 lines or 20 files. Past 1000 lines or 50 files, post
as `should` and name the split.
say: "This is ~N hand-written lines across M files. Was this size agreed in the
ticket? If not, a stack of smaller PRs (each builds and tests alone) reviews
faster and is less likely to be sent back."
why: AGENTS.md "Keep the PR small". Large diffs against a privileged networking
daemon are a security cost, not only a time cost. Stacked PRs, each against
the branch below, are the preferred split.

### PROC-012 User-facing change has a docs PR
severity: should
scope: diff + PR body
check: the diff changes CLI flags or commands (`client/cmd`), service flags
(`management/cmd`, `signal/cmd`, `relay/cmd`), REST API (`openapi.yml`),
config file keys, setup-key or policy semantics, posture checks, or the UI,
and the Documentation section is ticked "not needed".
say: "This is user-facing (<what>). Either link the netbirdio/docs PR or say in
the Documentation section why docs are not needed."

## CI gates the agent can predict

Each of these is a workflow that will go red. Post the prediction as a
`blocker` with the fix, so the author does not wait for CI.

### PROC-020 `go mod tidy` leaves no diff
severity: blocker
scope: go.mod, go.sum, any import change
check: run `go mod tidy` on the branch and `git diff --exit-code`; every Go
test workflow does exactly this before testing. Flag an import of a new
module without a `go.mod` change, or a `go.sum` change with no `go.mod`
change.
why: `golang-test-*.yml` "check git status" step.

### PROC-021 No new `replace` directive in the root go.mod
severity: blocker
scope: go.mod
check: a `replace` line added to `/go.mod` that is not in `origin/main`.
say: "`no-new-replace.yml` fails on any added replace: a replace only applies
to the main module, so embedded clients that import netbird as a library break.
Require the fork under a path you control (as `github.com/netbirdio/go-nat`)."
why: [`.github/workflows/no-new-replace.yml`](../../.github/workflows/no-new-replace.yml).
Removing a replace is allowed and logged.

### PROC-022 Dependency add, remove, or bump needs the user's decision
severity: ask
scope: go.mod
check: a new `require` line, a removed one, or a version bump that the PR
title or body does not describe as its purpose.
say: "This bumps/adds `<module>`; was that intended as part of this change, and
has the licence been checked (`check-license-dependencies.yml` refuses
GPL/AGPL/LGPL reaching BSD-licensed packages)?"
why: AGENTS.md "STOP and ask the user before: adding, removing, or bumping a
dependency, and never vendor a fork."

### PROC-023 Generated protobuf carries the pinned tool versions
severity: blocker
scope: `**/*.pb.go`
check: the `// protoc`, `// protoc-gen-go`, `// - protoc-gen-go-grpc` header
lines of a modified `.pb.go` differ from the base branch.
say: "`proto-version-check.yml` fails: regenerate with the tool versions pinned
in the matching `generate.sh` so only the intended fields change."
why: [`.github/workflows/proto-version-check.yml`](../../.github/workflows/proto-version-check.yml).
See 30-generated.md for the per-directory generator rules.

### PROC-024 Proto changes pass `buf breaking`
severity: blocker
scope: `**/*.proto`, `buf.yaml`, `buf.gen.yaml`
check: a field removed, renumbered, retyped, or renamed; an enum value removed;
a message or RPC removed. Added fields and `reserved` ranges are fine.
say: "`buf.yml` runs `buf breaking` against the base. Released agents must keep
working against a new management, so add fields and reserve removed numbers;
never renumber."
why: [`.github/workflows/buf.yml`](../../.github/workflows/buf.yml) and
AGENTS.md Pitfalls.

### PROC-025 Activity codes stay unique
severity: blocker
scope: `management/server/activity/codes.go`
check: a new constant in the `const (` block reuses an existing numeric value,
or a value is edited. Values are append-only; the dashboard and stored events
key on them.
say: "The lint workflow greps `codes.go` for duplicate `= N` values; pick the
next free number and never renumber."
why: `golangci-lint.yml` "Check for duplicate constants".

### PROC-026 Codespell
severity: nit
scope: all text files except the skip list in `golangci-lint.yml`
check: obvious misspellings in identifiers, comments, docs. The ignore list in
the workflow is the source of truth for intentional words.

### PROC-027 Licence boundary between BSD and AGPL packages
severity: blocker
scope: imports
check: a non-test file outside `management/`, `signal/`, `relay/`, `proxy/`,
`combined/`, `tools/idp-migrate/` imports
`github.com/netbirdio/netbird/(management|signal|relay|proxy)/...`.
say: "`check-license-dependencies.yml` fails: `<pkg>` is BSD-licensed and may
not import the AGPL services. Move the shared piece under `shared/` or a
root-level package."
why: [`.github/workflows/check-license-dependencies.yml`](../../.github/workflows/check-license-dependencies.yml).
The same job rejects GPL-family external modules reachable from BSD code.

### PROC-028 Cross-platform build still compiles
severity: blocker
scope: `client/**`, `util/**`, `sharedsock/**`, `route/**`, `dns/**`
check: a new platform-specific file (`_linux.go`, `_windows.go`, `_darwin.go`,
`_freebsd.go`, `//go:build` constraint) that introduces a symbol used from
platform-neutral code without a counterpart or fallback for the other targets.
The test matrix builds Linux (amd64 and 386), macOS, Windows, FreeBSD; mobile
and WASM have validation workflows.
say: "`<symbol>` is only defined for `<os>`; `golang-test-<other>.yml` will fail
to compile. Add the counterpart or a build-tagged stub."
why: AGENTS.md Repo-wide principles 9; `mobile-build-validation.yml`,
`wasm-build-validation.yml`.

### PROC-029 Never edit a workflow, threshold, exclusion, or bot config to pass
severity: blocker
scope: `.github/**`, `.golangci.yaml`, `.coderabbit.yaml`, `codecov*`,
`sonar-project.properties`
check: a change to these files inside a PR whose purpose is not CI itself.
say: "This loosens a check (<which>). If the check is wrong, say so in the PR
and let a maintainer decide; do not change it alongside the code it would have
flagged."
why: AGENTS.md "After you push".

## After the review

- A finding the author answered with a reason is closed, not re-posted on the
  next push.
- A bot comment (CodeRabbit, Sonar, Snyk) the agent can verify as wrong gets a
  short reply saying why, in the thread; it is never bulk-resolved.
- Security findings from any bot are surfaced to the human reviewer, not
  dismissed by an agent.
