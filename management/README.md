# netbird Management Server
netbird management server will control and synchronize peers configuration within your Netbird account and network.

## Command Options
The CLI accepts the command **management** with the following options:
```shell
start Netbird Management Server

Usage:
  netbird-mgmt management [flags]

Flags:
      --cert-file string            Location of your SSL certificate. Can be used when you have an existing certificate and don't want a new certificate be generated automatically. If letsencrypt-domain is specified this property has no effect
      --cert-key string             Location of your SSL certificate private key. Can be used when you have an existing certificate and don't want a new certificate be generated automatically. If letsencrypt-domain is specified this property has no effect
      --datadir string              server data directory location
  -h, --help                        help for management
      --letsencrypt-domain string   a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS
      --port int                    server port to listen on (default 33073)

Global Flags:
      --config string      Netbird config file location to write new config to (default "/etc/netbird")
      --log-file string    sets Netbird log path. If console is specified the the log will be output to stdout (default "/var/log/netbird/management.log")
      --log-level string    (default "info")
```
## Run Management service (Docker)

You can run service in 2 modes - with TLS or without (not recommended).

### Run with TLS (Let's Encrypt). 
By specifying the **--letsencrypt-domain** the daemon will handle SSL certificate request and configuration.

In the following example ```33073``` is the management service **default** port, and ```443``` will be used as port for Let's Encrypt challenge and HTTP API.
> The server where you are running a container has to have a public IP (for Let's Encrypt certificate challenge).

Replace <YOUR-DOMAIN> with your server's public domain (e.g. mydomain.com or subdomain sub.mydomain.com).

```bash
# create a volume
docker volume create netbird-mgmt
# run the docker container
docker run -d --name netbird-management \
-p 33073:33073  \
-p 443:443  \
-v netbird-mgmt:/var/lib/netbird  \
-v ./config.json:/etc/netbird/config.json  \
netbirdio/management:latest \
--letsencrypt-domain <YOUR-DOMAIN>
```
> An example of config.json can be found here [management.json](../infrastructure_files/management.json.tmpl)

Trigger Let's encrypt certificate generation:
```bash
curl https://<YOUR-DOMAIN>
```

The certificate will be persisted in the ```datadir/letsencrypt/``` folder (e.g. ```/var/lib/netbird/letsencrypt/```) inside the container.

Make sure that the ```datadir``` is mapped to some folder on a host machine. In case you used the volume command, you can run the following to retrieve the Mountpoint:
```shell
docker volume inspect netbird-mgmt
[
    {
        "CreatedAt": "2021-07-25T20:45:28Z",
        "Driver": "local",
        "Labels": {},
        "Mountpoint": "/var/lib/docker/volumes/mgmt/_data",
        "Name": "netbird-mgmt",
        "Options": {},
        "Scope": "local"
    }
]
```
Consequent restarts of the container will pick up previously generated certificate so there is no need to trigger certificate generation with the ```curl``` command on every restart.

### Run without TLS.

```bash
# create a volume
docker volume create netbird-mgmt
# run the docker container
docker run -d --name netbird-management \
-p 33073:33073  \
-v netbird-mgmt:/var/lib/netbird  \
-v ./config.json:/etc/netbird/config.json  \
netbirdio/management:latest
```
### Debug tag
We also publish a docker image with the debug tag which has the log-level set to default, plus it uses the ```gcr.io/distroless/base:debug``` image that can be used with docker exec in order to run some commands in the Management container.
```shell
shell $ docker run -d --name netbird-management-debug \
-p 33073:33073  \
-v netbird-mgmt:/var/lib/netbird  \
-v ./config.json:/etc/netbird/config.json  \
netbirdio/management:debug-latest

shell $ docker exec -ti netbird-management-debug /bin/sh
container-shell $ 
```
## For development purposes:

Install golang gRpc tools:
```bash
#!/bin/bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
```

Generate gRpc code:

```bash
#!/bin/bash
protoc -I proto/ proto/management.proto --go_out=. --go-grpc_out=.
```

