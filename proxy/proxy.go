package proxy

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
	"sync"

	"github.com/klauspost/compress/zstd"
)

const strTCP = "tcp"

type TCPProxy struct {
	localPort    uint
	localTLS     bool
	localZstd    bool
	remoteAddr   string
	remoteTLS    bool
	remoteZstd   bool
	localConfig  tls.Config
	remoteConfig tls.Config
	logData      bool
	stdoutMutex  sync.Mutex
	// remoteCert   string
	// peerCert     string
}

func NewTCPProxy(localPort uint, localTLS, localZstd bool, remoteAddr string, remoteTLS, remoteZstd bool, localCrt, localKey, remoteCrt, peerCrt string, logData bool) (*TCPProxy, error) {
	if len(remoteAddr) == 0 {
		return nil, fmt.Errorf("remote address is required")
	}
	proxy := &TCPProxy{
		localPort:  localPort,
		localTLS:   localTLS,
		localZstd:  localZstd,
		remoteAddr: remoteAddr,
		remoteTLS:  remoteTLS,
		remoteZstd: remoteZstd,
		logData:    logData,
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
	log.Printf("Listening on %s proxying to %s (local tls: %t, local zstd: %t, remote tls: %t, remote zstd: %t)", listen.Addr(), p.remoteAddr, p.localTLS, p.localZstd, p.remoteTLS, p.remoteZstd)

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
	if p.logData {
		log.Println("Connected to remote:", remote.RemoteAddr(), "id:", connID)
	}

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

	var connReader io.Reader = conn
	var connWriter io.Writer = conn
	var remoteReader io.Reader = remote
	var remoteWriter io.Writer = remote

	if p.localZstd {
		connReader, err = zstd.NewReader(conn, zstd.WithDecoderConcurrency(1))
		if err != nil {
			log.Println("Error creating local zstd reader:", err, "id:", connID)
			return
		}
		defer connReader.(*zstd.Decoder).Close()
		connWriter, err = zstd.NewWriter(conn, zstd.WithEncoderConcurrency(1))
		if err != nil {
			log.Println("Error creating local zstd writer:", err, "id:", connID)
			return
		}
		defer connWriter.(*zstd.Encoder).Close()
	}

	if p.remoteZstd {
		remoteReader, err = zstd.NewReader(remote, zstd.WithDecoderConcurrency(1))
		if err != nil {
			log.Println("Error creating remote zstd reader:", err, "id:", connID)
			return
		}
		defer remoteReader.(*zstd.Decoder).Close()
		remoteWriter, err = zstd.NewWriter(remote, zstd.WithEncoderConcurrency(1))
		if err != nil {
			log.Println("Error creating remote zstd writer:", err, "id:", connID)
			return
		}
		defer remoteWriter.(*zstd.Encoder).Close()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if p.logData {
			name := fmt.Sprintf("connID: %d  remote -> local", connID)
			CopyConn(name, connWriter, remoteReader, &p.stdoutMutex)
		} else {
			io.Copy(connWriter, remoteReader)
		}
	}()
	go func() {
		defer wg.Done()
		if p.logData {
			name := fmt.Sprintf("connID: %d  local -> remote", connID)
			CopyConn(name, remoteWriter, connReader, &p.stdoutMutex)
		} else {
			io.Copy(remoteWriter, connReader)
		}
	}()
	wg.Wait()
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
		MinVersion:   tls.VersionTLS13,
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
		MinVersion:         tls.VersionTLS13,
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
