package main

import (
	"flag"
	"fmt"
)

func main() {
	var localPort uint
	flag.UintVar(&localPort, "local-port", 0, "local port")
	var localTLS bool
	flag.BoolVar(&localTLS, "local-tls", false, "local tls")
	var remoteAddr string
	flag.StringVar(&remoteAddr, "remote-addr", "", "remote addr")
	var remoteTLS bool
	flag.BoolVar(&remoteTLS, "remote-tls", false, "remote tls")
	var localCrt string
	flag.StringVar(&localCrt, "local-crt", "cert/local.crt", "local crt")
	var localKey string
	flag.StringVar(&localKey, "local-key", "cert/local.key", "local key")
	var remoteCrt string
	flag.StringVar(&remoteCrt, "remote-crt", "cert/remote.crt", "remote crt")
	var peerCrt string
	flag.StringVar(&peerCrt, "peer-crt", "cert/peer.crt", "peer crt")

	flag.Parse()

	proxy, err := NewTCPProxy(localPort, localTLS, remoteAddr, remoteTLS, localCrt, localKey, remoteCrt, peerCrt)
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
