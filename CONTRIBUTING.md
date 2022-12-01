# Contributing to NetBird

Thanks for your interest in contributing to NetBird. 

There are many ways that you can contribute:
- Reporting issues
- Updating documentation
- Sharing use cases in slack or Reddit
- Bug fix or feature enhancement

If you haven't already, join our slack workspace [here](https://join.slack.com/t/netbirdio/shared_invite/zt-vrahf41g-ik1v7fV8du6t0RwxSrJ96A), we would love to discuss topics that need community contribution and enhancements to existing features.

## Contents

- [Contributing to NetBird](#contributing-to-netbird)
    - [Contents](#contents)
    - [Code of conduct](#code-of-conduct)
    - [Directory structure](#directory-structure)
    - [Development setup](#development-setup)
        - [Requirements](#requirements)
        - [Local NetBird setup](#local-netbird-setup)
        - [Build and start](#build-and-start)
        - [Test suite](#test-suite)
    - [Checklist before submitting a PR](#checklist-before-submitting-a-pr)
    - [Other project repositories](#other-project-repositories)
    - [Checklist before submitting a new node](#checklist-before-submitting-a-new-node)
    - [Contributor License Agreement](#contributor-license-agreement)

## Code of conduct

This project and everyone participating in it are governed by the Code of
Conduct which can be found in the file [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report
unacceptable behavior to dev@netbird.io.

## Directory structure

The NetBird project monorepo is organized to maintain most of its individual dependencies code within their directories, except for a few auxiliary or shared packages.

The most important directories are:

- [/.github](/.github) - Github actions workflow files and issue templates
- [/client](/client) - NetBird agent code
- [/client/cmd](/client/cmd) - NetBird agent cli code
- [/client/internal](/client/internal) - NetBird agent business logic code
- [/client/proto](/client/proto) - NetBird agent daemon GRPC proto files
- [/client/server](/client/server) - NetBird agent daemon code for background execution
- [/client/ui](/client/ui) - NetBird agent UI code
- [/encryption](/encryption) - Contain main encryption code for agent communication
- [/iface](/iface) - Wireguard® interface code
- [/infrastructure_files](/infrastructure_files) - Getting started files containing docker and template scripts
- [/management](/management) - Management service code
- [/management/client](/management/client) - Management service client code which is imported by the agent code
- [/management/proto](/management/proto) - Management service GRPC proto files
- [/management/server](/management/server) - Management service server code
- [/management/server/http](/management/server/http) - Management service REST API code
- [/management/server/idp](/management/server/idp) - Management service IDP management code
- [/release_files](/release_files) - Files that goes into release packages
- [/signal](/signal) - Signal service code
- [/signal/client](/signal/client) - Signal service client code which is imported by the agent code
- [/signal/peer](/signal/peer) - Signal service peer message logic
- [/signal/proto](/signal/proto) - Signal service GRPC proto files
- [/signal/server](/signal/server) - Signal service server code


## Development setup

If you want to contribute to bug fixes or improve existing features, you have to ensure that all needed
dependencies are installed. Here is a short guide on how that can be done.

### Requirements

#### Go 1.19

Follow the installation guide from https://go.dev/

#### UI client - Fyne toolkit 

We use the fyne toolkit in our UI client. You can follow its requirement guide to have all its dependencies installed: https://developer.fyne.io/started/#prerequisites

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
goreleaser --snapshot --rm-dist
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

### Build and start
#### Client

> Windows clients have a Wireguard driver requirement. We provide a bash script that can be executed in WLS 2 with docker support [wireguard_nt.sh](/client/wireguard_nt.sh).

To start NetBird, execute:
```
cd client
# bash wireguard_nt.sh # if windows
go build .
```

To start NetBird the client in the foreground:

```
sudo ./client up --log-level debug --log-file console
```
> On Windows use a powershell with administrator privileges
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

### Test suite

The tests can be started via:

```
cd netbird
go test -exec sudo ./...
```
> On Windows use a powershell with administrator privileges

## Checklist before submitting a PR
As a critical network service and open-source project, we must enforce a few things before submitting the pull-requests:
- Keep functions as simple as possible, with a single purpose
- Use private functions and constants where possible
- Comment on any new public functions
- Add unit tests for any new public function

> When pushing fixes to the PR comments, please push as separate commits; we will squash the PR before merging, so there is no need to squash it before pushing it, and we are more than okay with 10-100 commits in a single PR. This helps review the fixes to the requested changes.

## Other project repositories

NetBird project is composed of 3 main repositories:
- NetBird: This repository, which contains the code for the agents and control plane services.
- Dashboard: https://github.com/netbirdio/dashboard, contains the Administration UI for the management service
- Documentations: https://github.com/netbirdio/docs, contains the documentation from https://netbird.io/docs

## Contributor License Agreement

That we do not have any potential problems later it is sadly necessary to sign a [Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md). That can be done literally with the push of a button.

A bot will automatically comment on the pull request once it got opened asking for the agreement to be signed. Before it did not get signed it is sadly not possible to merge it in.