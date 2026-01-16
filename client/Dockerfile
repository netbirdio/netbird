# build & run locally with:
#   cd "$(git rev-parse --show-toplevel)"
#   CGO_ENABLED=0 go build -o netbird ./client
#   sudo podman build -t localhost/netbird:latest -f client/Dockerfile --ignorefile .dockerignore-client .
#   sudo podman run --rm -it --cap-add={BPF,NET_ADMIN,NET_RAW} localhost/netbird:latest

FROM alpine:3.23.2
# iproute2: busybox doesn't display ip rules properly
RUN apk add --no-cache \
    bash \
    ca-certificates \
    ip6tables \
    iproute2 \
    iptables

ENV \
    NETBIRD_BIN="/usr/local/bin/netbird" \
    NB_LOG_FILE="console,/var/log/netbird/client.log" \
    NB_DAEMON_ADDR="unix:///var/run/netbird.sock" \
    NB_ENTRYPOINT_SERVICE_TIMEOUT="5" \
    NB_ENTRYPOINT_LOGIN_TIMEOUT="5"

ENTRYPOINT [ "/usr/local/bin/netbird-entrypoint.sh" ]

ARG NETBIRD_BINARY=netbird
COPY client/netbird-entrypoint.sh /usr/local/bin/netbird-entrypoint.sh
COPY "${NETBIRD_BINARY}"  /usr/local/bin/netbird
