# Security Policy

NetBird's goal is to provide a secure network. The client runs as a privileged service on every machine it is installed on,
so we take reports about it seriously and we publish what we fix.

## Reporting a Vulnerability

**Please do not open a public issue for a security vulnerability.** Public issues are visible to everyone, including before
a fix is available.

Report security issues one of these two ways:

- **GitHub private vulnerability reporting** — [open a private report](https://github.com/netbirdio/netbird/security/advisories/new)
  on this repository. This is the preferred route: it keeps the discussion, the draft advisory, and the credit in one place.
- **Email** — `security@netbird.io`.

If the finding affects NetBird Cloud or our hosted infrastructure rather than the open source code, email us rather than
filing a repository report.

### What to include

A report is easier to act on when it contains:

- The affected component (client, management, signal, relay, dashboard) and the version or commit you tested
- The platform and configuration, where relevant — operating system, self-hosted or NetBird Cloud, container or host install
- What an attacker needs before they can exploit it: network position, an account, local access, a specific privilege level
- Steps to reproduce, and a proof of concept if you have one
- The impact you believe it has

Partial reports are still welcome. If you are unsure whether something is a security issue, send it to `security@netbird.io`
and let us make that call.

## What to expect from us

- **We acknowledge your report** and tell you whether we can reproduce it.
- **We work with you on severity and scope.** If we assess it differently than you do, we will explain why rather than
  silently downgrade it.
- **We fix and release**, then publish a [GitHub Security Advisory](https://github.com/netbirdio/netbird/security/advisories)
  naming the affected version range and the patched version.
- **We credit reporters who want to be credited.** Tell us the name or handle you would like used, or that you would rather
  stay anonymous.
- **We keep you in the loop** until the advisory is published.

We ask that you give us a reasonable opportunity to ship a fix before disclosing the issue publicly, and that you avoid
accessing, modifying, or exfiltrating data belonging to other people while testing. Testing against your own installation
or your own account is always fine.

## Supported Versions

We support the latest release. Security fixes ship in the next version rather than as backports to older releases, so
upgrading to the current release is how you get them.

Release notifications are available by watching [releases](https://github.com/netbirdio/netbird/releases).

## Published advisories

Every vulnerability we fix is published as a GitHub Security Advisory on the
[advisories page](https://github.com/netbirdio/netbird/security/advisories), including the affected version range, the
patched version, and the reporter's credit. Advisories for the Go module are also distributed through the Go vulnerability
database, so `govulncheck` will report them against your dependencies.

## Bug bounty

There is no official bug bounty program for the NetBird project. We credit reporters in advisories, and we are grateful for
the work, but we cannot currently offer payment for reports.

## Non-security bugs

For bugs that are not security issues, please use the
[issue tracker](https://github.com/netbirdio/netbird/discussions/new/choose).
