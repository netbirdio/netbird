FROM gcr.io/distroless/base:debug
ENTRYPOINT [ "/go/bin/wiretrustee","management"]
CMD ["--log-level","DEBUG", "--datadir", "/var/lib/wiretrustee/"]
COPY wiretrustee /go/bin/wiretrustee