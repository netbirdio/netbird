FROM golang:bookworm as builder

RUN apt-get update && apt-get install -y gcc-aarch64-linux-gnu

RUN git clone https://github.com/netbirdio/netbird.git
WORKDIR netbird

COPY management/server/idp/zitadel.go management/server/idp/zitadel.go

RUN CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64 go build -o netbird-mgmt -a ./management

FROM arm64v8/debian

COPY --from=builder /go/netbird/netbird-mgmt /usr/local/bin

ENTRYPOINT ["netbird-mgmt"]
