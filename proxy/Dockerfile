FROM ubuntu:24.04
RUN apt update && apt install -y ca-certificates && rm -fr /var/cache/apt
ENTRYPOINT [ "/go/bin/netbird-proxy"]
CMD []
COPY netbird-proxy /go/bin/netbird-proxy
