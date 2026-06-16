FROM alpine:3.24
RUN apk add --no-cache bash ca-certificates
ENTRYPOINT [ "/go/bin/netbird-upload" ]
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/netbird-upload /go/bin/netbird-upload
