FROM golang:alpine as builder

RUN apk add git

RUN go build -o netbird-mgmt -a ./management

FROM alpine

COPY --from=builder /go/netbird/netbird-mgmt /usr/local/bin

ENTRYPOINT ["netbird-mgmt"]
