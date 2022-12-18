FROM golang:latest AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" .

FROM debian:latest
RUN \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -yq ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    exit 0
COPY ./cert /app/cert
COPY --from=builder /app/gotcpproxy /app/gotcpproxy
ENTRYPOINT ["/app/gotcpproxy"]
