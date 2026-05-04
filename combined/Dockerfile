FROM ubuntu:24.04
RUN apt update && apt install -y ca-certificates && rm -fr /var/cache/apt
ENTRYPOINT [ "/go/bin/netbird-server" ]
CMD ["--config", "/etc/netbird/config.yaml"]
COPY netbird-server /go/bin/netbird-server