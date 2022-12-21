package main

import (
	"flag"
	"fmt"

	"github.com/fffaraz/gotcpproxy/proxy"
)

func main() {
	var localPort uint
	flag.UintVar(&localPort, "local-port", 0, "local port")
	var localTLS bool
	flag.BoolVar(&localTLS, "local-tls", false, "local tls")
	var localZstd bool
	flag.BoolVar(&localZstd, "local-zstd", false, "local zstd")

	var remoteAddr string
	flag.StringVar(&remoteAddr, "remote-addr", "", "remote addr")
	var remoteTLS bool
	flag.BoolVar(&remoteTLS, "remote-tls", false, "remote tls")
	var remoteZstd bool
	flag.BoolVar(&remoteZstd, "remote-zstd", false, "remote zstd")

	var localCrt string
	flag.StringVar(&localCrt, "local-crt", "cert/local.crt", "local crt")
	var localKey string
	flag.StringVar(&localKey, "local-key", "cert/local.key", "local key")

	var remoteCrt string
	flag.StringVar(&remoteCrt, "remote-crt", "cert/remote.crt", "remote crt")

	var peerCrt string
	flag.StringVar(&peerCrt, "peer-crt", "cert/peer.crt", "peer crt")

	var logData bool
	flag.BoolVar(&logData, "log-data", false, "log data")

	flag.Parse()

	proxy, err := proxy.NewTCPProxy(localPort, localTLS, localZstd, remoteAddr, remoteTLS, remoteZstd, localCrt, localKey, remoteCrt, peerCrt, logData)
	if err != nil {
		fmt.Println("ERROR:", err)
		flag.Usage()
		return
	}
	if err := proxy.Run(); err != nil {
		fmt.Println("ERROR:", err)
		flag.Usage()
		return
	}
}
