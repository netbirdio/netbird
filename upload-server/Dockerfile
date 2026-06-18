FROM gcr.io/distroless/base:debug
ENTRYPOINT [ "/go/bin/netbird-upload" ]
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/netbird-upload /go/bin/netbird-upload
