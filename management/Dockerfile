FROM ubuntu:22.04
RUN apt update && apt install -y ca-certificates && rm -fr /var/cache/apt
ENTRYPOINT [ "/go/bin/netbird-mgmt","management"]
CMD ["--log-file", "console"]
COPY netbird-mgmt /go/bin/netbird-mgmt