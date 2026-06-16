FROM alpine:3.24
RUN apk add --no-cache bash ca-certificates
ENTRYPOINT [ "/go/bin/netbird-signal","run" ]
CMD ["--log-file", "console"]
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/netbird-signal /go/bin/netbird-signal
