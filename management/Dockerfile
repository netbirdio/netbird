FROM gcr.io/distroless/base:debug
ENTRYPOINT [ "/go/bin/wiretrustee","management"]
CMD ["--log-level","DEBUG", "--config", "/etc/wiretrustee/management.json"]
COPY wiretrustee /go/bin/wiretrustee