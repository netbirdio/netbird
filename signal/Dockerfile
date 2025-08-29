FROM gcr.io/distroless/base:debug
ENTRYPOINT [ "/go/bin/netbird-signal","run" ]
CMD ["--log-file", "console"]
COPY netbird-signal /go/bin/netbird-signal
