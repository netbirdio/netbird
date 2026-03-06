FROM golang:1.25-alpine AS build
WORKDIR /app
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -o ingest .

FROM alpine:3.20
COPY --from=build /app/ingest /usr/local/bin/ingest
ENTRYPOINT ["ingest"]