FROM docker.io/golang:1.16 AS build

WORKDIR /src

COPY go.mod .
COPY cmd .
COPY connection .
COPY iface .
COPY signal .
COPY util .
COPY main.go .

RUN go mod download
RUN go mod tidy
RUN go install .

FROM gcr.io/distroless/base
COPY --from=build /go/bin/wiretrustee /
ENTRYPOINT [ "/wiretrustee signal" ]
