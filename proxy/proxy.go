package proxy

import (
	"compress/gzip"
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
)

const strTCP = "tcp"

type TCPProxy struct {
	localPort    uint
	localTLS     bool
	localZip     bool
	remoteAddr   string
	remoteTLS    bool
	remoteZip    bool
	localConfig  tls.Config
	remoteConfig tls.Config
	logData      bool
	stdoutMutex  sync.Mutex
	nagles       bool
	// bytesSent    uint64
	// bytesRecv    uint64
}

func NewTCPProxy(localPort uint, localTLS, localZip bool, remoteAddr string, remoteTLS, remoteZip bool, localCrt, localKey, remoteCrt, peerCrt string, logData bool) (*TCPProxy, error) {
	if len(remoteAddr) == 0 {
		return nil, fmt.Errorf("remote address is required")
	}
	proxy := &TCPProxy{
		localPort:  localPort,
		localTLS:   localTLS,
		localZip:   localZip,
		remoteAddr: remoteAddr,
		remoteTLS:  remoteTLS,
		remoteZip:  remoteZip,
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
	log.Printf("Listening on %s proxying to %s (local-tls: %t, local-zip: %t, remote-tls: %t, remote-zip: %t)", listen.Addr(), p.remoteAddr, p.localTLS, p.localZip, p.remoteTLS, p.remoteZip)

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
	}

	if p.nagles {
		if err := conn.(*net.TCPConn).SetNoDelay(false); err != nil {
			log.Println("Error setting local nagle:", err, "id:", connID)
			return
		}
		if err := remote.(*net.TCPConn).SetNoDelay(false); err != nil {
			log.Println("Error setting remote nagle:", err, "id:", connID)
			return
		}
	}

	var connReader io.Reader = conn
	var connWriter io.Writer = conn
	var remoteReader io.Reader = remote
	var remoteWriter io.Writer = remote

	if p.localZip {
		connReader, _ = gzip.NewReader(conn)
		defer connReader.(*gzip.Reader).Close()
		connWriter, _ = gzip.NewWriterLevel(conn, gzip.BestSpeed)
		defer connWriter.(*gzip.Writer).Close()
	}

	if p.remoteZip {
		remoteReader, _ = gzip.NewReader(remote)
		defer remoteReader.(*gzip.Reader).Close()
		remoteWriter, _ = gzip.NewWriterLevel(remote, gzip.BestSpeed)
		defer remoteWriter.(*gzip.Writer).Close()
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

	return nil
}
