FROM golang:bookworm as builder

# RUN apt-get update && apt-get install -y gcc-aarch64-linux-gnu

RUN git clone https://github.com/netbirdio/netbird.git
WORKDIR netbird

COPY management/server/idp/zitadel.go management/server/idp/zitadel.go
COPY management/server/idp/idp.go management/server/idp/idp.go

RUN CGO_ENABLED=1 go build -o netbird-mgmt -a ./management

FROM debian

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

COPY --from=builder /go/netbird/netbird-mgmt /usr/local/bin

ENTRYPOINT ["netbird-mgmt", "management"]
