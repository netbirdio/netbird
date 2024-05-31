FROM golang:alpine as builder

RUN apk add git

RUN git clone https://github.com/netbirdio/netbird.git
WORKDIR netbird

COPY management/server/idp/zitadel.go management/server/idp/zitadel.go

RUN CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 go build -o netbird-mgmt -a ./management

FROM alpine

COPY --from=builder /go/netbird/netbird-mgmt /usr/local/bin

ENTRYPOINT ["netbird-mgmt"]
