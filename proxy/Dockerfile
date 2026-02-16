FROM golang:1.25-alpine AS builder
WORKDIR /app

RUN echo "netbird:x:1000:1000:netbird:/var/lib/netbird:/sbin/nologin" > /tmp/passwd && \
    echo "netbird:x:1000:netbird" > /tmp/group && \
    mkdir -p /tmp/var/lib/netbird && \
    mkdir -p /tmp/certs

FROM gcr.io/distroless/base:debug
COPY netbird-proxy /go/bin/netbird-proxy
COPY --from=builder /tmp/passwd /etc/passwd
COPY --from=builder /tmp/group /etc/group
COPY --from=builder /tmp/var/lib/netbird /var/lib/netbird
COPY --from=builder --chown=1000:1000 --chmod=755 /tmp/certs /certs
USER netbird:netbird
ENV HOME=/var/lib/netbird
ENV NB_PROXY_ADDRESS=":8443"
EXPOSE 8443
ENTRYPOINT ["/go/bin/netbird-proxy"]
