FROM alpine:3.18.5
RUN apk add --no-cache ca-certificates iptables ip6tables
ENV NB_FOREGROUND_MODE=true
ENTRYPOINT [ "/usr/local/bin/netbird","up"]
COPY netbird /usr/local/bin/netbird