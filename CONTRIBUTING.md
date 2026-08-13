# Contributing to NetBird

Thanks for your interest in contributing to NetBird.

There are many ways that you can contribute:
- Reporting issues
- Updating documentation
- Sharing use cases in slack or Reddit
- Bug fix or feature enhancement

If you haven't already, join our slack workspace [here](https://docs.netbird.io/slack-url), we would love to discuss topics that need community contribution and enhancements to existing features.

## Ticket first, PR second

**Open a ticket and wait for feedback before you open a pull request.** Every PR
that changes behavior must link to an issue the NetBird team has agreed on. A PR
that arrives without one may be closed and redirected to a discussion, no matter
how good the code is.

Issues in this repository are maintainer-curated work items, so the flow starts
in [Discussions](https://github.com/netbirdio/netbird/discussions):

1. **Open a discussion.** Use
   [Issue Triage](https://github.com/netbirdio/netbird/discussions/new?category=issue-triage)
   for a bug, regression, or unexpected behavior, and
   [Ideas & Feature Requests](https://github.com/netbirdio/netbird/discussions/new?category=ideas-feature-requests)
   for a feature, enhancement, or integration idea. Setup and usage questions
   belong in
   [Q&A / Support](https://github.com/netbirdio/netbird/discussions/new?category=q-a-support).
   Never report a security vulnerability in public — follow the
   [security policy](https://github.com/netbirdio/netbird/security/policy)
   instead.
2. **Wait for feedback.** DevRel validates and reproduces the report, and a
   maintainer confirms the direction. We may ask for more detail or propose a
   different approach. Validated discussions become issues.
3. **Then write the code**, following the approach agreed in the issue, and open
   the PR linking that issue.

Trivial fixes — a typo, a broken link, a documentation correction, or a one-line
fix that already has an issue — can go straight to a PR. Everything else starts
with a ticket. When in doubt, ask in the discussion or on
[Slack](https://docs.netbird.io/slack-url); an hour of conversation up front
regularly saves a week of rework.

### High-risk areas

These always need the design discussed and agreed in the issue **before** you
write code:

- **Public API** — REST / management API, OpenAPI schema, dashboard-facing contracts
- **gRPC protocols** — management, signal, relay, and client daemon protos
- **Functionality behavior** — anything existing deployments would experience differently after an upgrade
- **Peer connectivity** — ICE and NAT traversal, relay selection, WireGuard® and Rosenpass key handling
- **Client system integration** — routing, firewall, DNS, and interface management
- **Authentication and authorization** — IdP integration, tokens, permissions, cryptography
- **CLI / service flags**, configuration file format, and daemon IPC
- **Store and database schema** — models and migrations
- **New features**

These surfaces are NetBird's contract with operators, self-hosters, and
downstream integrators, and changes to them have compatibility, security, and
release-planning implications. Agreeing on the direction early lets the PR
review focus on implementation rather than design.

Typical bug fixes, internal refactors, documentation updates, and tests do not
need a design discussion, but should still be tied to an issue so the work is
visible and nobody duplicates it.

### Using AI coding agents

We have no policy for or against using an AI agent to write NetBird code. That
choice is yours, and we are not going to interrogate anyone about their tools.

What we do have is a lot of incoming contributions that were plainly drafted with
one, and enough experience reviewing them to see the same avoidable problems
again and again: no ticket behind the change, a diff far too large to review, a
description longer than the code it describes, an approach that was never going
to be accepted, and an author who cannot answer questions about their own PR.
None of that is caused by the tooling — it is what happens when a tool is pointed
at a repository whose expectations it has never been told.

So rather than a rule, there is a guide. [AGENTS.md](AGENTS.md) restates the
expectations from this document in the form agents read automatically
(`CLAUDE.md` points to it), so pointing your tool at the repository is usually
enough. Among other things it tells the agent to ask you for the
discussion or issue before drafting a PR, to keep the change small and
single-purpose, to run the tests locally, to use this repository's PR template
and title tags, and to write a description a reviewer can get through.

The guardrails are the point, and they are the same ones we apply to everyone: an
agreed ticket, a change you have actually run, a diff small enough to review with
care, and an author who can explain it. Whatever wrote the diff, you are its
author — you own every line you submit and the consequences of opening a PR with it.

We may assess whether a contribution is maintainable and whether its merged code
aligns with our security standards and design expectations.

## Contents

- [Contributing to NetBird](#contributing-to-netbird)
    - [Ticket first, PR second](#ticket-first-pr-second)
        - [High-risk areas](#high-risk-areas)
        - [Using AI coding agents](#using-ai-coding-agents)
    - [Contents](#contents)
    - [Code of conduct](#code-of-conduct)
    - [Directory structure](#directory-structure)
    - [Development setup](#development-setup)
        - [Requirements](#requirements)
        - [Local NetBird setup](#local-netbird-setup)
        - [Dev Container Support](#dev-container-support)
        - [Build and start](#build-and-start)
        - [Test suite](#test-suite)
    - [Checklist before submitting a PR](#checklist-before-submitting-a-pr)
    - [When we close a PR](#when-we-close-a-pr)
    - [Translations](#translations)
    - [Other project repositories](#other-project-repositories)
    - [Contributor License Agreement](#contributor-license-agreement)

## Code of conduct

This project and everyone participating in it are governed by the Code of
Conduct which can be found in the file [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report
unacceptable behavior to community@netbird.io.

## Directory structure

The NetBird project monorepo keeps most of each component's code within its own
directory, except for a few auxiliary or shared packages. Protocol definitions
and the client-side service clients live under [/shared](/shared), because both
the agent and the services import them.

**Agent**

- [/client](/client) - NetBird agent code
- [/client/cmd](/client/cmd) - NetBird agent CLI code
- [/client/internal](/client/internal) - NetBird agent business logic code
- [/client/server](/client/server) - NetBird agent daemon code for background execution
- [/client/proto](/client/proto) - NetBird agent daemon gRPC proto files
- [/client/iface](/client/iface) - WireGuard® interface code
- [/client/firewall](/client/firewall) - Platform firewall backends (nftables, iptables, pf, WFP, userspace)
- [/client/ssh](/client/ssh) - Built-in SSH server and client
- [/client/ui](/client/ui) - NetBird agent UI code (Wails v3 + React)
- [/client/android](/client/android), [/client/ios](/client/ios) - Mobile platform bindings
- [/client/wasm](/client/wasm) - WebAssembly build of the agent
- [/client/mdm](/client/mdm) - MDM-delivered policy handling
- [/client/system](/client/system) - Host and system information collection

**Control plane services**

- [/management](/management) - Management service code
- [/management/server](/management/server) - Management service server code
- [/management/server/http](/management/server/http) - Management service REST API code
- [/management/server/store](/management/server/store) - Persistence layer and migrations
- [/management/server/idp](/management/server/idp) - Management service IDP management code
- [/management/server/peer](/management/server/peer), [/management/server/groups](/management/server/groups), [/management/server/networks](/management/server/networks), [/management/server/posture](/management/server/posture), [/management/server/permissions](/management/server/permissions) - Core domain packages
- [/signal](/signal) - Signal service code
- [/signal/peer](/signal/peer) - Signal service peer message logic
- [/signal/server](/signal/server) - Signal service server code
- [/relay](/relay) - Relay service code
- [/relay/protocol](/relay/protocol) - Relay wire protocol
- [/proxy](/proxy) - Identity-aware proxy used by Agent Network (LLM routing, ACME, access logs)
- [/agent-network](/agent-network) - Agent Network overview and documentation
- [/upload-server](/upload-server) - Debug bundle upload service

**Shared code**

- [/shared/management/proto](/shared/management/proto) - Management service gRPC proto files
- [/shared/management/client](/shared/management/client) - Management service client code which is imported by the agent code
- [/shared/management/http/api](/shared/management/http/api) - OpenAPI specification and generated REST API types
- [/shared/signal/proto](/shared/signal/proto) - Signal service gRPC proto files
- [/shared/signal/client](/shared/signal/client) - Signal service client code which is imported by the agent code
- [/shared/relay](/shared/relay) - Relay client and shared relay types
- [/shared/auth](/shared/auth), [/shared/sshauth](/shared/sshauth) - Shared authentication primitives
- [/encryption](/encryption) - Contain main encryption code for agent communication
- [/dns](/dns), [/route](/route), [/stun](/stun), [/sharedsock](/sharedsock), [/util](/util) - Shared networking and utility primitives
- [/flow](/flow) - Flow event protocol shared by the agent and Management

**Build, test, and packaging**

- [/.github](/.github) - Github actions workflow files, issue templates, and the pull request template
- [/e2e](/e2e) - End-to-end test suites and harness
- [/infrastructure_files](/infrastructure_files) - Getting started files containing docker and template scripts
- [/release_files](/release_files) - Files that goes into release packages
- [/tools](/tools) - Development and maintenance tooling


## Development setup

If you want to contribute to bug fixes or improve existing features, you have to ensure that all needed
dependencies are installed. Here is a short guide on how that can be done.

### Requirements

#### Go 1.25

Follow the installation guide from https://go.dev/

#### UI client - Wails v3 + React

The desktop UI client (`client/ui`) is built with [Wails v3](https://v3.wails.io/) and a React frontend rendered in a WebView. To build it you need:

- Go ≥ 1.25
- Node ≥ 20 and **pnpm** (`corepack enable && corepack prepare pnpm@latest --activate`)
- The `wails3` CLI: `go install github.com/wailsapp/wails/v3/cmd/wails3@latest`
- The `task` runner: `go install github.com/go-task/task/v3/cmd/task@latest`
- Linux only: `libwebkitgtk-6.0-dev`, `libgtk-4-dev`, `libsoup-3.0-dev`

All UI build, dev-loop, and cross-compile commands are described in the [UI client](#ui-client) section below.

#### gRPC
You can follow the instructions from the quickstarter guide https://grpc.io/docs/languages/go/quickstart/#prerequisites and then run the `generate.sh` files located in each `proto` directory to generate changes.
> **IMPORTANT**: We are very open to contributions that can improve the client daemon protocol. For Signal and Management protocols, please reach out on slack or via github issues with your proposals.

#### Docker

Follow the installation guide from https://docs.docker.com/get-docker/

#### Goreleaser and golangci-lint

We utilize two tools in our Github actions workflows:
- Goreleaser: Used for release packaging. You can follow the installation steps [here](https://goreleaser.com/install/); keep in mind to match the version defined in [release.yml](/.github/workflows/release.yml)
- golangci-lint: Used for linting checks. You can follow the installation steps [here](https://golangci-lint.run/usage/install/); keep in mind to match the version defined in [golangci-lint.yml](/.github/workflows/golangci-lint.yml)

They can be executed from the repository root before every push or PR:

**Goreleaser**
```shell
goreleaser build --snapshot --clean
```
**golangci-lint**
```shell
golangci-lint run
```

### Local NetBird setup

> **IMPORTANT**: All the steps below have to get executed at least once to get the development setup up and running!

Now that everything NetBird requires to run is installed, the actual NetBird code can be
checked out and set up:

1. [Fork](https://guides.github.com/activities/forking/#fork) the NetBird repository

2. Clone your forked repository

   ```
   git clone https://github.com/<your_github_username>/netbird.git
   ```

3. Go into the repository folder

   ```
   cd netbird
   ```

4. Add the original NetBird repository as `upstream` to your forked repository

   ```
   git remote add upstream https://github.com/netbirdio/netbird.git
   ```

5. Install all Go dependencies:

   ```
   go mod tidy
   ```

6. Configure Git hooks for automatic linting:

   ```bash
   make setup-hooks
   ```

   This will configure Git to run linting automatically before each push, helping catch issues early.

### Dev Container Support

If you prefer using a dev container for development, NetBird now includes support for dev containers. 
Dev containers provide a consistent and isolated development environment, making it easier for contributors to get started quickly. Follow the steps below to set up NetBird in a dev container.

#### 1. Prerequisites:

* Install Docker on your machine: [Docker Installation Guide](https://docs.docker.com/get-docker/)
* Install Visual Studio Code: [VS Code Installation Guide](https://code.visualstudio.com/download)
* If you prefer JetBrains Goland please follow this [manual](https://www.jetbrains.com/help/go/connect-to-devcontainer.html)

#### 2. Clone the Repository:

Clone the repository following previous [Local NetBird setup](#local-netbird-setup).

#### 3. Open in project in IDE of your choice:

**VScode**:

Open the project folder in Visual Studio Code:

```bash
code .
```

When you open the project in VS Code, it will detect the presence of a dev container configuration.
Click on the green "Reopen in Container" button in the bottom-right corner of VS Code.

**Goland**:

Open GoLand and select `"File" > "Open"` to open the NetBird project folder.
GoLand will detect the dev container configuration and prompt you to open the project in the container. Accept the prompt.

#### 4. Wait for the Container to Build:

VsCode or GoLand will use the specified Docker image to build the dev container. This might take some time, depending on your internet connection.

#### 6. Development:

Once the container is built, you can start developing within the dev container. All the necessary dependencies and configurations are set up within the container.


### Build and start
#### Client

To start NetBird, execute:
```
cd client
CGO_ENABLED=0 go build .
```

> Windows clients have a Wireguard driver requirement. You can download the wintun driver from https://www.wintun.net/builds/wintun-0.14.1.zip, after decompressing, you can copy the file `windtun\bin\ARCH\wintun.dll` to the same path as your binary file or to `C:\Windows\System32\wintun.dll`.

> To test the client GUI application on Windows machines with RDP or vituralized environments (e.g. virtualbox or cloud), you need to download and extract the opengl32.dll from https://fdossena.com/?p=mesa/index.frag next to the built application.

To start NetBird the client in the foreground:

```
sudo ./client up --log-level debug --log-file console
```
> On Windows use a powershell with administrator privileges

#### UI client

The desktop UI lives in `client/ui` and is built with Wails v3 (see [Requirements](#ui-client---wails-v3--react)). All commands run from `client/ui`.

Live-reload development (Vite + Go binary + `*.go` watcher):

```
cd client/ui
task dev
```

Pass daemon flags after `--`, pointing the UI at the socket the daemon serves:

```
task dev -- --daemon-addr=unix:///var/run/netbird.sock   # Linux, macOS
task dev -- --daemon-addr=npipe://netbird                # Windows
```

On Windows the daemon serves a named pipe (`npipe://netbird`). Which path that
ends up being depends on what the daemon may create: as a service or elevated it
serves `\\.\pipe\ProtectedPrefix\Administrators\netbird`, which no unprivileged
process can take from it, and otherwise it falls back to `\\.\pipe\netbird`.
Clients try both and check who owns the pipe before using the plain one. Avoid
`tcp://127.0.0.1:41731`: loopback TCP carries no caller identity, so the daemon
refuses the operations that require an administrator and you will not exercise
those paths.

Production build (frontend assets embedded into the binary, output in `client/ui/bin/`):

```
cd client/ui
task build
```

Cross-compile the Windows binary from Linux (requires the mingw-w64 toolchain, e.g. `sudo apt install gcc-mingw-w64-x86-64`):

```
CGO_ENABLED=1 task windows:build
```

> macOS cross-compile from Linux is not supported (signing and notarization need a real Mac).

#### Signal service

To start NetBird's signal, execute:

```
cd signal
go build .
```

To start NetBird the signal service:

```
./signal run --log-level debug --log-file console
```

#### Management service
> You may need to generate a configuration file for management. Follow steps 2 to 5 from our [self-hosting guide](https://netbird.io/docs/getting-started/self-hosting).

To start NetBird's management, execute:

```
cd management
go build .
```

To start NetBird the management service:

```
./management management --log-level debug --log-file console --config ./management.json
```

#### Windows Netbird Installer
Create dist directory
```shell
mkdir -p dist/netbird_windows_amd64
```

UI client (built with Wails v3 — see the [UI client](#ui-client) section above)
```shell
(cd client/ui && CGO_ENABLED=1 task windows:build)
mv client/ui/bin/netbird-ui.exe ./dist/netbird_windows_amd64/
```

Client
```shell
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o netbird.exe ./client/
mv netbird.exe ./dist/netbird_windows_amd64/
```
> Windows clients have a Wireguard driver requirement. You can download the wintun driver from https://www.wintun.net/builds/wintun-0.14.1.zip, after decompressing, you can copy the file `windtun\bin\ARCH\wintun.dll` to `./dist/netbird_windows_amd64/`.

NSIS compiler
- [Windows-nsis]( https://nsis.sourceforge.io/Download)
- [MacOS-makensis](https://formulae.brew.sh/formula/makensis#default)
- [Linux-makensis](https://manpages.ubuntu.com/manpages/trusty/man1/makensis.1.html)

NSIS Plugins. Download and move them to the NSIS plugins folder.
- [EnVar](https://nsis.sourceforge.io/mediawiki/images/7/7f/EnVar_plugin.zip)
- [ShellExecAsUser](https://nsis.sourceforge.io/mediawiki/images/6/68/ShellExecAsUser_amd64-Unicode.7z)

Windows Installer
```shell
export APPVER=0.0.0.1
makensis -V4 client/installer.nsis
```

The installer `netbird-installer.exe` will be created in root directory.

### Test suite

The host-safe unit tests run as a normal user and leave host networking
untouched:

```
make test-unit
```

Tests that need root and mutate host networking (firewall, routing, interface
management) carry the `privileged` build tag and run inside a
`--privileged --cap-add=NET_ADMIN` Docker container:

```
make test-privileged
```

Narrow a privileged run with environment variables:

```
PRIV_RUN=TestNftablesManager PRIV_PKGS=./client/firewall/nftables/... make test-privileged
```

Single packages can be run directly, adding `-race` when the change touches
shared state:

```
go test -race ./client/internal/dns/...
```

> On Windows use a powershell with administrator privileges

## Checklist before submitting a PR

As a critical network service and open-source project, we must enforce a few
things before submitting a pull request. The
[pull request template](/.github/pull_request_template.md) mirrors this list —
fill it in rather than deleting it.

### Link the issue

The PR description must link the agreed issue (or the validated discussion it
came from). See [Ticket first, PR second](#ticket-first-pr-second).

### Run it locally

**If you can't run it, you can't submit it.** Build the affected components and
exercise the change on a real setup — see [Build and start](#build-and-start).
"CI will tell me" is not acceptable for a VPN agent that runs as root on other
people's machines.

### Green CI, and answer the bots

We do not start reviewing while CI is red. Get the pipeline green first — a
failing build, lint, or test means the PR is not ready for review.

Alongside the test workflows, your PR is reviewed by CodeRabbit and scanned by
SonarCloud, Snyk, and Codecov. Read what they report and either fix it or reply
with why it does not apply; please do not resolve the threads without a
response. They are not always right — this codebase has privileged,
platform-specific, and concurrency-heavy paths that static analysis reads poorly
— so push back when a finding is wrong rather than changing correct code to
silence it. Security and dependency findings are the exception: treat those as
real until shown otherwise. Do not edit workflows, thresholds, or scanner
configuration to make a check pass.

### One PR, one purpose

Bug fix, refactor, feature: separate PRs. Mixed PRs are slow to review, hard to
revert, and may be closed with a request to split them.

### Keep it small

Size is the strongest predictor of how long a PR waits for review. Aim for under
roughly 400 changed lines across under 20 files. Past about 1000 lines or 50
files, expect to be asked to split the change — and large PRs from outside the
core team may be blocked until the scope has been agreed in a ticket. This is
not only about reviewer time: NetBird's agent runs as root on other people's
machines, and a sprawling diff cannot be reviewed with the care that deserves.

Measure by hand-written code, excluding generated output, `go.sum`, and
fixtures. If a change genuinely cannot be small — a protocol migration, a
cross-component rename — agree the split in the issue before you start, and land
it as a series of PRs that each build and make sense on their own.

### Avoid force-pushing during review

Once a PR is open, push new commits instead of rewriting history. A force-push
detaches existing review comments from their lines, throws away the
"changes since your last review" diff, and loses the CI history that showed
which commit broke what. Since we squash on merge, there is nothing to gain from
a tidy branch history.

Force-pushing is sometimes unavoidable — rebasing to clear a real conflict, or
removing a secret or large binary committed by mistake. When that happens, leave
a comment on the PR so reviewers know their anchors moved.

### Quality checks

Run these from the repository root before pushing:

```shell
go fmt ./...
make lint        # golangci-lint on files changed against origin/main
make lint-all    # full-repository lint, matches CI
make test-unit   # host-safe unit tests
```

`make setup-hooks` wires `make lint` into a pre-push hook so the fast lint runs
automatically. If your change touches privileged paths (firewall, routing,
interface management), also run `make test-privileged`, which executes the
`privileged`-tagged suite inside a Docker container with `NET_ADMIN`.

### Code standards

- Keep functions as simple as possible, with a single purpose
- Use private functions and constants where possible
- Comment on any new public functions
- Add unit tests for any new public function
- Comment the **why**, not the **what** — explain non-obvious decisions, invariants, and constraints, not the line below
- Keep comments within 90 characters per line and roughly 250 characters per comment; when a block needs more explanation than that, extract a named function instead of writing a longer comment (see [AGENTS.md](AGENTS.md#length-budget))

### PR title and commits

PR titles must start with a bracketed tag, enforced by
[pr-title-check.yml](/.github/workflows/pr-title-check.yml):

```text
[client] Authorize daemon IPC callers by their local identity
[management,client] Add MDM policy support
```

Use a comma-separated list inside a single pair of brackets when a change spans
components. The `allowedTags` array in
[pr-title-check.yml](/.github/workflows/pr-title-check.yml) is the source of
truth — at the time of writing it accepts `management`, `client`, `signal`,
`proxy`, `relay`, `misc`, `infrastructure`, `self-hosted`, and `doc`.

Commit subjects follow the same convention — keep them short and put the
reasoning in the body, why before what, with no bullet list of files changed.

Keep the PR description itself under 1000 words on top of the template text.
Reviewers read the diff; the description explains what the diff cannot.

> When pushing fixes to the PR comments, please push as separate commits; we will squash the PR before merging, so there is no need to squash it before pushing it, and we are more than okay with 10-100 commits in a single PR. This helps review the fixes to the requested changes.

### Documentation

User-facing changes need a matching PR in
[netbirdio/docs](https://github.com/netbirdio/docs); link it in the PR
description, or state why documentation is not needed.

## When we close a PR

We would rather redirect early than let a PR sit. We may close one if:

- It changes behavior with no linked issue, or the approach was never agreed with a maintainer
- The change was clearly never run or tested locally
- CI has been red without a response
- It mixes unrelated purposes, or the purpose is not clear
- It is far too large to review and the scope was never agreed in a ticket
- The author cannot answer questions about their own change — including PRs that read as unreviewed model output, where review turns into a relay between the maintainer and an LLM. Tooling is fine; unreviewed output is not, you are responsible for the code you sign your name to
- There has been no activity for 14 days after we requested changes

A closed PR is not a rejected idea. Take it back to the
[discussion](https://github.com/netbirdio/netbird/discussions), settle the
approach, and reopen the work from there.

## Translations

Desktop UI translations are not contributed through pull requests. Translate on
[Crowdin](https://crowdin.com/project/netbird) instead: no ticket needed, just
join the project and pick your language. Crowdin syncs with this repository and
opens the service PRs itself, so hand-edited locale files would conflict with
the next sync. Style, terminology, and review guidance live in
[client/ui/i18n/TRANSLATING.md](client/ui/i18n/TRANSLATING.md). To request a
language the project does not offer yet, ask on the Crowdin project page or in
a [discussion](https://github.com/netbirdio/netbird/discussions).

## Other project repositories

NetBird project is composed of 3 main repositories:
- NetBird: This repository, which contains the code for the agents and control plane services.
- Dashboard: https://github.com/netbirdio/dashboard, contains the Administration UI for the management service
- Documentations: https://github.com/netbirdio/docs, contains the documentation from https://netbird.io/docs

## Contributor License Agreement

That we do not have any potential problems later it is sadly necessary to sign a [Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md). That can be done literally with the push of a button.

A bot will automatically comment on the pull request once it got opened asking for the agreement to be signed. Before it did not get signed it is sadly not possible to merge it in.
