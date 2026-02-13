FROM gcr.io/distroless/base:debug
ENTRYPOINT ["/go/bin/netbird-proxy"]
ENV NB_PROXY_ADDRESS=":8443"
COPY netbird-proxy /go/bin/netbird-proxy
