# netbird Signal Server

This is a netbird signal-exchange server and client library to exchange
connection information between netbird peers

## Command Options

The CLI accepts the the following options:

```shell
start Netbird Signal Server daemon

Usage:
  netbird-signal run [flags]

Flags:
  -h, --help                        help for run
      --letsencrypt-domain string   a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS
      --port int                    Server port to listen on (e.g. 10000) (default 10000)
      --ssl-dir string              server ssl directory location. *Required only for Let's Encrypt certificates. (default "/var/lib/netbird/")
      --cert-file string            Location of your SSL certificate. Can be used when you have an existing certificate and don't want a new certificate be generated automatically. If letsencrypt-domain is specified this property has no effect
      --cert-key string             Location of your SSL certificate private key. Can be used when you have an existing certificate and don't want a new certificate be generated automatically. If letsencrypt-domain is specified this property has no effect

Global Flags:
      --log-file string    sets Netbird log path. If console is specified the the log will be output to stdout (default "/var/log/netbird/signal.log")
      --log-level string    (default "info")
```

## Running the Signal service (Docker)

We have packed the Signal server into docker image. You can pull the image from
Docker Hub and execute it with the
following commands:

````shell
docker pull netbirdio/signal:latest
docker run -d --name netbird-signal -p 10000:10000 netbirdio/signal:latest
````

The default log-level is set to INFO, if you need you can change it using by
updating the docker cmd as followed:

````shell
docker run -d --name netbird-signal -p 10000:10000 netbirdio/signal:latest --log-level DEBUG
````

### Run with TLS (Let's Encrypt).

By specifying the **--letsencrypt-domain** the daemon will handle SSL
certificate request and configuration.

In the following example ```10000``` is the signal service **default** port,
and ```443``` will be used as port for
Let's Encrypt challenge and HTTP API.
> The server where you are running a container has to have a public IP (for
> Let's Encrypt certificate challenge).

Replace `<YOUR-DOMAIN>` with your server's public domain (e.g. mydomain.com or
subdomain sub.mydomain.com).

```bash
# create a volume
docker volume create netbird-signal
# run the docker container
docker run -d --name netbird-signal \
-p 10000:10000  \
-p 443:443  \
-v netbird-signal:/var/lib/netbird  \
netbirdio/signal:latest \
--letsencrypt-domain <YOUR-DOMAIN>
```

## Metrics

The Signal Server exposes the following metrics in Prometheus format:

### Application Metrics

- **active_peers**: A Gauge metric that tracks the number of active peers
  connected to the server.
- **peer_connection_duration_seconds**: A Histogram metric that measures the
  duration a peer was connected in seconds.
- **registrations_total**: A Counter metric that counts the total number of peer
  registrations.
- **deregistrations_total**: A Counter metric that counts the total number of
  peer deregistrations.
- **registration_failures_total**: A Counter metric that counts the total number
  of failed peer registrations. Possible
  labels:
  - `error`: The type of error that caused the registration failure (
      e.g., `missing_id`, `missing_meta`, `failed_header`).
- **registration_delay_milliseconds**: A Histogram metric that measures the time
  it took to register a peer in
  milliseconds.
- **get_registration_delay_milliseconds**: A Histogram metric that measures the time
  it took to get a peer registration in
  milliseconds.
- **messages_forwarded_total**: A Counter metric that counts the total number of
  messages forwarded between peers.
- **message_forward_failures_total**: A Counter metric that counts the total
  number of failed message forwards between
  peers. Possible labels:
  - `type`: The type of failure (
      e.g., `error`, `not_connected`, `not_registered`).
- **message_forward_latency_milliseconds**: A Histogram metric that measures the
  latency of message forwarding between
  peers in milliseconds.

### Endpoint

The metrics are exposed in Prometheus format on the `/metrics` endpoint. By
default, the server listens on port `9090`,
so the full endpoint would be:

> http://<server_ip>:9090/metrics

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
