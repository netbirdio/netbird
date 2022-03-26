# netbird Signal Server

This is a netbird signal-exchange server and client library to exchange connection information between netbird peers

## Command Options
The CLI accepts the command **management** with the following options:
```shell
start Wiretrustee Signal Server daemon

Usage:
  wiretrustee-signal run [flags]

Flags:
  -h, --help                        help for run
      --letsencrypt-domain string   a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS
      --port int                    Server port to listen on (e.g. 10000) (default 10000)
      --ssl-dir string              server ssl directory location. *Required only for Let's Encrypt certificates. (default "/var/lib/wiretrustee/")

Global Flags:
      --log-level string    (default "info")
      --log-file string    sets Wiretrustee log path. If console is specified the the log will be output to stdout (default "/var/log/wiretrustee/management.log")
```
## Running the Signal service (Docker)

We have packed the Signal server into docker image. You can pull the image from Docker Hub and execute it with the following commands:
````shell
docker pull wiretrustee/signal:latest
docker run -d --name wiretrustee-signal -p 10000:10000 wiretrustee/signal:latest
````
The default log-level is set to INFO, if you need you can change it using by updating the docker cmd as followed:
````shell
docker run -d --name wiretrustee-signal -p 10000:10000 wiretrustee/signal:latest --log-level DEBUG
````
### Run with TLS (Let's Encrypt).
By specifying the **--letsencrypt-domain** the daemon will handle SSL certificate request and configuration.

In the following example ```10000``` is the signal service **default** port, and ```443``` will be used as port for Let's Encrypt challenge and HTTP API.
> The server where you are running a container has to have a public IP (for Let's Encrypt certificate challenge).

Replace <YOUR-DOMAIN> with your server's public domain (e.g. mydomain.com or subdomain sub.mydomain.com).

```bash
# create a volume
docker volume create wiretrustee-signal
# run the docker container
docker run -d --name wiretrustee-management \
-p 10000:10000  \
-p 443:443  \
-v wiretrustee-signal:/var/lib/wiretrustee  \
wiretrustee/signal:latest \
--letsencrypt-domain <YOUR-DOMAIN>
```
## For development purposes:

The project uses gRpc library and defines service in protobuf file located in:
 ```proto/signalexchange.proto```

To build the project you have to do the following things.

Install golang gRpc tools:
```bash
#!/bin/bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
```

Generate gRpc code:

```bash
#!/bin/bash
protoc -I proto/ proto/signalexchange.proto --go_out=. --go-grpc_out=.
```
