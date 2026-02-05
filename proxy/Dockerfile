FROM golang:1.25-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o netbird-proxy ./proxy/cmd/proxy

RUN echo "netbird:x:1000:1000:netbird:/var/lib/netbird:/sbin/nologin" > /tmp/passwd && \
    echo "netbird:x:1000:netbird" > /tmp/group && \
    mkdir -p /tmp/var/lib/netbird && \
    mkdir -p /tmp/certs

FROM gcr.io/distroless/base:debug
COPY --from=builder /app/netbird-proxy /usr/bin/netbird-proxy
COPY --from=builder /tmp/passwd /etc/passwd
COPY --from=builder /tmp/group /etc/group
COPY --from=builder --chown=1000:1000 /tmp/var/lib/netbird /var/lib/netbird
COPY --from=builder --chown=1000:1000 /tmp/certs /certs
USER netbird:netbird
ENV HOME=/var/lib/netbird
ENV NB_PROXY_ADDRESS=":8443"
EXPOSE 8443
ENTRYPOINT ["/usr/bin/netbird-proxy"]
