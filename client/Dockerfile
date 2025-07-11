FROM alpine:3.22.0
# iproute2: busybox doesn't display ip rules properly
RUN apk add --no-cache \
    bash \
    ca-certificates \
    ip6tables \
    iproute2 \
    iptables

ENV \
    NETBIRD_BIN="/usr/local/bin/netbird" \
    NB_LOG_FILE="/var/log/netbird/client.log" \
    NB_DAEMON_ADDR="unix:///var/run/netbird.sock" \
    NB_ENTRYPOINT_SERVICE_TIMEOUT="5" \
    NB_ENTRYPOINT_LOGIN_TIMEOUT="1" \
    NB_ENTRYPOINT_TAIL_LOG_FILE="true"

ENTRYPOINT [ "/usr/local/bin/netbird-entrypoint.sh" ]

ARG NETBIRD_BINARY=netbird
COPY client/netbird-entrypoint.sh /usr/local/bin/netbird-entrypoint.sh
COPY "${NETBIRD_BINARY}"  /usr/local/bin/netbird
