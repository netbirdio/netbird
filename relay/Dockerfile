FROM gcr.io/distroless/base:debug
ENTRYPOINT [ "/go/bin/netbird-relay" ]
ENV NB_LOG_FILE=console
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/netbird-relay /go/bin/netbird-relay
