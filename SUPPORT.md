# Getting help with NetBird

Where to go depends on what you need. If you are not sure, start with
[Q&A / Support](https://github.com/netbirdio/netbird/discussions/new?category=q-a-support)
and we will move it.

## Before you post

1. Search existing [discussions](https://github.com/netbirdio/netbird/discussions) and
   [issues](https://github.com/netbirdio/netbird/issues), including closed ones.
2. Check the [documentation](https://docs.netbird.io) and the troubleshooting guides for
   [clients](https://docs.netbird.io/help/troubleshooting-client) and
   [self-hosted deployments](https://docs.netbird.io/selfhosted/troubleshooting).
3. Remove or anonymize sensitive information from logs, screenshots, and configuration.

If a discussion already covers your problem, upvote it and add your details there rather than
opening a duplicate. Extra reproduction detail, affected versions, and deployment notes are
useful even on an existing thread.

## Community support

Free, for everyone. Covers the NetBird client, open source self-hosted deployments, and general
questions.

| What you want to do | Where to go |
| --- | --- |
| Report a bug, regression, or unexpected behavior | [Issue Triage](https://github.com/netbirdio/netbird/discussions/new?category=issue-triage) |
| Request a feature or share an idea | [Ideas & Feature Requests](https://github.com/netbirdio/netbird/discussions/new?category=ideas-feature-requests) |
| Ask about setup, configuration, or self-hosting | [Q&A / Support](https://github.com/netbirdio/netbird/discussions/new?category=q-a-support) |
| Chat with the community | [Slack](https://docs.netbird.io/slack-url) |

## Paid support

For NetBird Cloud customers and commercial-license self-hosted deployments, covering the
dashboard, control plane, billing, and subscriptions, see
[reporting bugs and issues](https://docs.netbird.io/help/report-bug-issues).

## Security

Do not report security vulnerabilities in public issues or discussions, and do not post secrets,
private keys, internal hostnames, or sensitive logs. Use the
[security policy](https://github.com/netbirdio/netbird/security/policy).

## What makes a report we can act on

For a bug, the most useful reports include:

- NetBird version, and component versions where applicable
- Operating system or environment
- Deployment type: NetBird Cloud, self-hosted, Kubernetes, Docker, or local development
- Current behavior and expected behavior
- The smallest set of steps that reproduces the problem
- Logs, status output, screenshots, or a debug bundle when relevant
- Whether this worked before, and the last known working version

For client reports, these commands usually give us what we need:

```shell
netbird version
netbird status -d -A
netbird debug for 1m -A -S -U
```

`-A` (`--anonymize`) replaces sensitive values consistently across every file in the bundle, so
it stays readable while masking most identifying details. It is not a guarantee of full redaction:
internal address ranges survive at the default level, and interface names, indexes, MTUs, and
flags are never anonymized. Read the bundle before posting it publicly. Two levels are
available:

| Level | How to select | What it masks |
| --- | --- | --- |
| `default` | `-A` / `--anonymize`, or `--anonymize-level default` | Public IP addresses, IPv6 ULA addresses, MAC addresses, and domains other than `netbird.io`, `netbird.cloud`, `netbird.selfhosted`, and `netbird.stage`. IPv4 private, CGNAT, and link-local ranges are kept, and interface names are not anonymized |
| `strict` | `--anonymize-level strict` (implies `-A`) | The above, plus IPv4 private, CGNAT, and link-local ranges, peer names in front of `netbird.cloud`, `netbird.selfhosted`, and `netbird.stage`, and WireGuard public keys. Labels under `netbird.io` are kept, since it only hosts infrastructure |

Use `strict` when internal addressing or peer naming is itself sensitive. Either way, private
keys and SSH keys are never included, and the packet capture (`capture.pcap`) is left out of
anonymized bundles because it holds raw decrypted packets.

`-U` (`--upload-bundle`) uploads the bundle and returns a file key you can paste into the thread
instead of attaching an archive. Retention is controlled by the upload service; check its policy
before uploading, and configure cleanup for self-hosted deployments.

For more detail, see [troubleshooting client issues](https://docs.netbird.io/help/troubleshooting-client),
which explains [what a debug bundle contains](https://docs.netbird.io/help/troubleshooting-client#debug-bundle),
and the [CLI reference](https://docs.netbird.io/get-started/cli#debug-for).

Intermittent problems are still worth reporting. They just need enough detail to investigate:
trigger, frequency, timing, timestamps, and any related logs.

For a feature request, describe the problem before the solution: what you are trying to
accomplish, who is affected and how often, why the current behavior or workaround is not enough,
and what you would like to see instead.

## What happens after you post

Our team, maintainers, or community members may ask for missing details, link related
threads, merge duplicates, move your post to a better category, or try to reproduce the problem.

Not every discussion becomes an issue. Some are answered in Q&A, some turn out to be
configuration problems, and some need more information before engineering can act. A
well-answered discussion is still a useful outcome.

When a report is confirmed and actionable, a maintainer opens a validated issue linked back to
the discussion, in whichever repository the fix belongs to. You do not need to know which
repository that is. Routing is part of triage.

## A note on issues

Issues in this repository are maintainer-curated work items. Every open issue is something a
maintainer or contributor can pick up and act on. Issues opened without a linked validated
discussion may be closed and redirected here.

Maintainers can still open issues directly for work found internally, such as regressions caught
during development, planned maintenance, or release blockers.

## Related reading

- [How to use Discussions, Issues, and Pull Requests](https://github.com/netbirdio/netbird/discussions/6075)
- [Moving to a discussion-first approach](https://github.com/netbirdio/netbird/discussions/6074)
- [CONTRIBUTING.md](CONTRIBUTING.md) for opening pull requests
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
