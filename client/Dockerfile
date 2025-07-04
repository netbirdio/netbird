FROM alpine:3.21.3
# iproute2: busybox doesn't display ip rules properly
RUN apk add --no-cache ca-certificates ip6tables iproute2 iptables

ARG NETBIRD_BINARY=netbird
COPY ${NETBIRD_BINARY} /usr/local/bin/netbird

ENV NB_FOREGROUND_MODE=true
ENTRYPOINT [ "/usr/local/bin/netbird","up"]
