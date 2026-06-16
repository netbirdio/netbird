FROM alpine:3.24
RUN apk add --no-cache bash ca-certificates
ENTRYPOINT [ "/go/bin/netbird-relay" ]
ENV NB_LOG_FILE=console
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/netbird-relay /go/bin/netbird-relay
