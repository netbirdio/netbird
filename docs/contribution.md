# Contribution

### To start developing Netbird
**You have a working Go environment**

Clone the project into your preferred path. We recommend just cloning into the GOPATH.
```
mkdir -p $GOPATH/src/github.com/netbirdio
cd $GOPATH/src/github.com/netbirdio
git clone git@github.com:netbirdio/netbird.git
cd netbird
go build ./...
```
**_Sidenote_** _`libayatana-appindicator3-dev` might be needed for developing on debian based distros._


**To run the tests execute:**

```
go test -exec sudo ./...
```
The tests need to be executed by a superuser,
because to run the integration tests we need to create network interfaces.


### Code Structure

The codebase is structured in 3 big components:
* Client
* Server
* Signal
* Dashboard (separate [repository](https://github.com/netbirdio/dashboard))

Refer to [architecture documentation](https://netbird.io/docs/overview/architecture) for more information.

---

### CLIENT
The Client consists of three different components.

##### Daemon

```
client/server     # daemon server that runs in the background
client/proto      # grpc daemon server listening to either the CLI or UI for requests
management/client # grpc client that connects to the management server
```
The Daemon runs in the background, and keeps the connection running.

##### CLI 
We use [Cobra](https://github.com/spf13/cobra) as our CLI framework
```
client/cmd          # All CLI commands are defined and implemented here
client/cmd/root.go  # All commands are registered in root.go
```

##### UI-App
We use [systray](https://github.com/getlantern/systray) and [fyne](https://github.com/fyne-io/fyne) to write a UI application for the Systemtray.
```
client/ui       # All UI elements implemented here 
```


---
### MANAGEMENT

```
management/cmd       # These are the CLI commands for starting the management server 
management/proto     # Management proto server for client
management/server    # This is the actual management server, responsible for IDP and managing
```


---
### SIGNAL

```
signal/server       
```


---
### DASHBOARD
