# NetBird review profile

This directory is the knowledge base for automated code review of the NetBird
repositories. It is written for review agents first and humans second: every
rule has an ID, a severity, a scope, and a check that can be applied to a diff
without judgement calls. Agents cite the rule ID when they comment, so a
developer can look it up, dispute it, or fix the rule instead of the comment.

The goal of the profile is to take the mechanical, repeatable findings off
human reviewers so their time goes to logic, design, and risk. A rule that
needs context the diff cannot give is written as a question for the human
reviewer, not as a finding.

The baseline conventions live in [AGENTS.md](../../AGENTS.md) and
[CONTRIBUTING.md](../../CONTRIBUTING.md). This profile does not repeat them in
prose; it turns them into checkable rules and adds what the code, the CI, and
the review history actually enforce.

## Files

| File | Scope | Used by |
| --- | --- | --- |
| [00-process.md](00-process.md) | PR title, template, ticket, size, docs, attribution, CI gates | every review agent, first pass |
| [10-go-style.md](10-go-style.md) | Go style, errors, comments, naming, logging, type safety, concurrency | every Go diff |
| [20-structure.md](20-structure.md) | Where code lives, package boundaries, license boundary, shared/ rules | every diff that adds a file or an import |
| [30-generated.md](30-generated.md) | OpenAPI, protobuf, mocks, go.mod, generate.sh and drift checks | diffs touching generated or spec files |
| [40-control-plane.md](40-control-plane.md) | Management, Signal, Relay, Proxy conventions | control-plane review agent |
| [50-client.md](50-client.md) | Agent (client) conventions: platforms, modes, lifecycle, system integration | client review agent |
| [60-testing.md](60-testing.md) | Test conventions and what a change must come with | every diff |
| [70-lessons.md](70-lessons.md) | What human reviewers keep asking for, mined from PR history | every agent, for calibration |

The private cloud repository carries its own profile for the cloud modules; it
refers back to this one for everything the submodule shares.

## Rule format

```text
### <ID> <title>
severity: blocker | should | nit | ask
scope: path globs the rule applies to
check: what to look for in the diff, mechanically
say: the one-line comment to post, in the repository's voice
why: the reason, with the source (AGENTS.md section, CI workflow, PR, file:line)
```

Severity meanings:

- **blocker**: request changes. Security, data loss, compatibility with
  released clients or existing deployments, host networking left dirty,
  a CI gate that will fail. A blocker is posted even when the agent is the
  only reviewer.
- **should**: post a comment; the author fixes it or replies with the reason
  it does not apply. Correctness and convention.
- **nit**: style and mechanical. Post as one batched comment or as a
  suggestion block; never as a change request, never more than one thread per
  file. If the repository's linter already reports it, do not post it at all.
- **ask**: the diff alone cannot decide. Post a question addressed to the
  human reviewer, state what would settle it, and do not block.

## Noise policy

The profile exists to remove noise, so these are hard rules for agents:

1. **Do not restate the linter.** `golangci-lint` with
   [`.golangci.yaml`](../../.golangci.yaml) runs on every PR on Linux, macOS,
   and Windows. Anything it reports (errcheck, gosec set, revive exported
   comments, staticcheck, unused, forbidigo on `fmt.Print*`, ...) is handled by
   CI. Mention it only when the PR has no green lint run yet and the fix is
   non-obvious.
2. **Do not restate the diff.** A comment describes a problem, not what the
   code does.
3. **One finding, one thread.** Repeated instances of the same nit go in one
   comment with a list of locations.
4. **Cite the rule ID** and the exact line. A finding that cannot name a rule
   or a concrete failure scenario is not posted.
5. **Never propose weakening a check to make something pass**: auth, TLS
   verification, privilege drop, peer identity, a failing test, a lint
   exclusion, a coverage threshold, a bot config.
6. **Security findings invert the default.** Where a diff touches
   authentication, authorization, certificate handling, key material, daemon
   RPC input, or firewall and routing state, assume a concern is real until the
   code disproves it, and post it as `blocker` or `ask`, never `nit`.
7. **Do not flag unused parameters in `shared/` or exported APIs** without
   asking; builds outside this repository consume them (AGENTS.md,
   Repo-wide principles 2).
8. **Prefer silence to a hedge.** "Consider whether..." without a concrete
   scenario is noise.

## How the profile is meant to be loaded

- A general review agent loads `00`, `10`, `20`, `30`, `60`, and `70` for every
  Go diff.
- The control-plane agent adds `40`; the client agent adds `50`. Pick by the
  paths in the diff, not by the PR title tag; a `[client]` PR that touches
  `shared/management/proto` still gets the compatibility rules.
- Cloud-specific agents load the cloud profile, which includes this one.
