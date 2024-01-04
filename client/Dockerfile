FROM alpine:3.18.5
RUN apk add --no-cache ca-certificates iptables ip6tables
ENV NB_FOREGROUND_MODE=true
ENTRYPOINT [ "/go/bin/netbird","up"]
COPY netbird /go/bin/netbird