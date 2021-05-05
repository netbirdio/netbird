FROM docker.io/golang:1.16 AS build

WORKDIR /src

COPY go.mod .
COPY . .

RUN go mod download
RUN go install .

FROM gcr.io/distroless/base
COPY --from=build /go/bin/wiretrustee-hub /
ENTRYPOINT [ "/wiretrustee-hub" ]
