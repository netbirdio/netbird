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
        - [Dev Container Support](#dev-container-support)
        - [Build and start](#build-and-start)
        - [Test suite](#test-suite)
    - [Checklist before submitting a PR](#checklist-before-submitting-a-pr)
    - [Other project repositories](#other-project-repositories)
    - [Contributor License Agreement](#contributor-license-agreement)

## Code of conduct

This project and everyone participating in it are governed by the Code of
Conduct which can be found in the file [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report
unacceptable behavior to community@netbird.io.

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

#### Go 1.21

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

UI client
```shell
CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -o netbird-ui.exe -ldflags "-s -w -H windowsgui" ./client/ui
mv netbird-ui.exe ./dist/netbird_windows_amd64/
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

The tests can be started via:

```
cd netbird
go test -exec sudo ./...
```
> On Windows use a powershell with administrator privileges

> Non-GTK environments will need the `libayatana-appindicator3-dev` (debian/ubuntu) package installed

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
