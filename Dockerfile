FROM gcr.io/distroless/base:debug
EXPOSE 10000
ENTRYPOINT [ "/go/bin/wiretrustee","signal" ]
CMD ["--log-level","DEBUG"]
COPY wiretrustee /go/bin/wiretrustee