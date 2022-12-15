package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const strTCP = "tcp"

type TCPProxy struct {
	localPort    uint
	localTLS     bool
	remoteAddr   string
	remoteTLS    bool
	localConfig  tls.Config
	remoteConfig tls.Config
	// remoteCert   string
	// peerCert     string
}

func NewTCPProxy(localPort uint, localTLS bool, remoteAddr string, remoteTLS bool, localCrt, localKey, remoteCrt, peerCrt string) (*TCPProxy, error) {
	if len(remoteAddr) == 0 {
		return nil, fmt.Errorf("remote addr is required")
	}
	proxy := &TCPProxy{
		localPort:  localPort,
		localTLS:   localTLS,
		remoteAddr: remoteAddr,
		remoteTLS:  remoteTLS,
	}
	if localTLS {
		if err := proxy.loadLocalCert(localCrt, localKey, peerCrt); err != nil {
			return nil, err
		}
	}
	if remoteTLS {
		if err := proxy.loadRemoteCert(localCrt, localKey, remoteCrt); err != nil {
			return nil, err
		}
	}
	return proxy, nil
}

func (p *TCPProxy) Run() error {
	var err error
	var listen net.Listener

	localAddr := fmt.Sprintf(":%d", p.localPort)
	if p.localTLS {
		listen, err = tls.Listen(strTCP, localAddr, &p.localConfig)
	} else {
		listen, err = net.Listen(strTCP, localAddr)
	}
	if err != nil {
		return err
	}
	defer listen.Close()
	log.Printf("Listening on %s proxying to %s (local tls: %t, remote tls: %t)", listen.Addr(), p.remoteAddr, p.localTLS, p.remoteTLS)

	connID := 0
	for {
		connID++
		conn, err := listen.Accept()
		if err != nil {
			log.Println("Error accepting connection:", connID, err)
			continue
		}
		go p.handleConnection(conn, connID)
	}
}

func (p *TCPProxy) handleConnection(conn net.Conn, connID int) {
	defer func() {
		conn.Close()
		log.Println("Closed connection:", connID)
	}()
	log.Println("Accepted connection from:", conn.RemoteAddr(), "id:", connID)

	if p.localTLS {
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			log.Println("Error handshaking local TLS:", err, "id:", connID)
			return
		}
		/*
			state := conn.(*tls.Conn).ConnectionState()
			if len(state.PeerCertificates) < 1 {
				log.Println("No local peer certificate found, id:", connID)
				return
			}
			cert := hex.EncodeToString(state.PeerCertificates[0].PublicKey.(ed25519.PublicKey))
			// log.Println("Local peer cert:", cert, "id:", connID)
			if cert != p.peerCert {
				log.Println("Local peer certificate does not match, id:", connID)
				return
			}
		*/
	}

	var err error
	var remote net.Conn

	if p.remoteTLS {
		remote, err = tls.Dial(strTCP, p.remoteAddr, &p.remoteConfig)
	} else {
		remote, err = net.Dial(strTCP, p.remoteAddr)
	}
	if err != nil {
		log.Println("Error dialing remote:", err, "id:", connID)
		return
	}
	defer remote.Close()

	if p.remoteTLS {
		if err := remote.(*tls.Conn).Handshake(); err != nil {
			log.Println("Error handshaking remote TLS:", err, "id:", connID)
			return
		}
		/*
			state := remote.(*tls.Conn).ConnectionState()
			if len(state.PeerCertificates) < 1 {
				log.Println("No remote peer certificate found, id:", connID)
				return
			}
			cert := hex.EncodeToString(state.PeerCertificates[0].PublicKey.(ed25519.PublicKey))
			// log.Println("Remote peer cert:", cert, "id:", connID)
			if cert != p.remoteCert {
				log.Println("Remote peer certificate does not match, id:", connID)
				return
			}
		*/
	}

	go io.Copy(conn, remote)
	io.Copy(remote, conn)
}

func (p *TCPProxy) loadLocalCert(localCrt, localKey, peerCrt string) error {
	cert, err := tls.LoadX509KeyPair(localCrt, localKey)
	if err != nil {
		log.Println("Error loading local cert/key:", localCrt, localKey, err)
		return err
	}
	log.Println("Local  cert:", hex.EncodeToString(cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)))

	caCertPEM, err := os.ReadFile(peerCrt)
	if err != nil {
		log.Println("Error loading peer cert:", peerCrt, err)
		return err
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCertPEM); !ok {
		log.Println("Error appending peer cert to pool", err)
		return err
	}

	p.localConfig = tls.Config{
		ClientCAs:    caCertPool,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	block, _ := pem.Decode(caCertPEM)
	peerCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Println("Error parsing peer cert:", err)
		return err
	}
	peerCertStr := hex.EncodeToString(peerCert.PublicKey.(ed25519.PublicKey))
	log.Println("Peer   cert:", peerCertStr)
	// p.peerCert = peerCertStr

	return nil
}

func (p *TCPProxy) loadRemoteCert(localCrt, localKey, remoteCrt string) error {
	cert, err := tls.LoadX509KeyPair(localCrt, localKey)
	if err != nil {
		log.Println("Error loading local cert/key:", localCrt, localKey, err)
		return err
	}
	log.Println("Local  cert:", hex.EncodeToString(cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)))

	caCertPEM, err := os.ReadFile(remoteCrt)
	if err != nil {
		log.Println("Error loading remote cert:", remoteCrt, err)
		return err
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCertPEM); !ok {
		log.Println("Error appending remote cert to pool", err)
		return err
	}

	p.remoteConfig = tls.Config{
		RootCAs:            caCertPool,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: false,
		ServerName:         "localhost",
	}

	block, _ := pem.Decode(caCertPEM)
	remoteCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Println("Error parsing remote cert:", err)
		return err
	}
	remoteCertStr := hex.EncodeToString(remoteCert.PublicKey.(ed25519.PublicKey))
	log.Println("Remote cert:", remoteCertStr)
	// p.remoteCert = remoteCertStr

	return nil
}
