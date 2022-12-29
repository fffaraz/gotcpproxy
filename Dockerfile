FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" .

FROM scratch
COPY ./cert /cert
COPY --from=builder /app/gotcpproxy /gotcpproxy
ENTRYPOINT ["/gotcpproxy"]
