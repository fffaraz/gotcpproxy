# GoTCPproxy
TCP over TLS Proxy in Go

## Generate certificates
```
for i in {1..3}; do
    openssl genpkey -algorithm ed25519 -out $i.key
    openssl req -new -x509 -sha256 -key $i.key -out $i.crt -days 3650 -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
done
```

## Build
```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" .
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" .
```

## Install
```
go install github.com/fffaraz/gotcpproxy@latest
```

## Use case 1
```
./gotcpproxy.exe -local-port 8080 -remote-addr 127.0.0.1:8081 -local-crt cert/1.crt -local-key cert/1.key -remote-crt cert/2.crt -remote-tls
./gotcpproxy.exe -local-port 8081 -remote-addr 192.168.1.2:22 -local-crt cert/2.crt -local-key cert/2.key -peer-crt cert/1.crt -local-tls
```

## Use case 2
```
./gotcpproxy.exe -local-port 8080 -remote-addr 127.0.0.1:8081 -local-crt cert/1.crt -local-key cert/1.key -remote-crt cert/2.crt -remote-tls
./gotcpproxy.exe -local-port 8081 -remote-addr 127.0.0.1:8082
./gotcpproxy.exe -local-port 8082 -remote-addr 192.168.1.2:22 -local-crt cert/2.crt -local-key cert/2.key -peer-crt cert/1.crt -local-tls
```

## Use case 3
```
./gotcpproxy.exe -local-port 8080 -remote-addr 127.0.0.1:8081 -local-crt cert/1.crt -local-key cert/1.key -remote-crt cert/2.crt -remote-tls
./gotcpproxy.exe -local-port 8081 -remote-addr 127.0.0.1:8082 -local-crt cert/2.crt -local-key cert/2.key -peer-crt cert/1.crt -remote-crt cert/3.crt -local-tls -remote-tls
./gotcpproxy.exe -local-port 8082 -remote-addr 192.168.1.2:22 -local-crt cert/3.crt -local-key cert/3.key -peer-crt cert/2.crt -local-tls
```

## Use case 4
```
./gotcpproxy.exe -local-port 8080 -remote-addr 192.168.1.2:22 -log-data
```

## HTTP/SOCKS5 Proxy
```
docker run -it --rm -p "127.0.0.13128:3128" ginuerzh/gost:latest -L=":3128?whitelist=tcp:*:80,443&dns=1.1.1.2"
```

## Docker compose
```
docker-compose -f docker-compose.client.yml up
docker-compose -f docker-compose.middle.yml up
docker-compose -f docker-compose.server.yml up
```
