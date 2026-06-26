FROM gcr.io/distroless/base:debug
ENTRYPOINT [ "/go/bin/netbird-signal","run" ]
CMD ["--log-file", "console"]
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/netbird-signal /go/bin/netbird-signal
