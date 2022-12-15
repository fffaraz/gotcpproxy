package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/textproto"
)

func PrintTLSConnState(conn *tls.Conn) {
	fmt.Println(">>>>>>>>>>>>>>>> TLS INFO <<<<<<<<<<<<<<<<")
	state := conn.ConnectionState()
	fmt.Printf("Version: %x\n", state.Version)
	fmt.Printf("HandshakeComplete: %t\n", state.HandshakeComplete)
	fmt.Printf("DidResume: %t\n", state.DidResume)
	fmt.Printf("CipherSuite: %x\n", state.CipherSuite)
	fmt.Printf("NegotiatedProtocol: %s\n", state.NegotiatedProtocol)
	fmt.Println("Certificate chain:")
	for i, cert := range state.PeerCertificates {
		subject := cert.Subject
		issuer := cert.Issuer
		fmt.Printf(" %d s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n", i, subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
		fmt.Printf("   i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n", issuer.Country, issuer.Province, issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)
		fmt.Println("Subject:", cert.Subject)
		fmt.Println("Issuer:", cert.Issuer)
		fmt.Println("Version:", cert.Version)
		fmt.Println("NotAfter:", cert.NotAfter)
		fmt.Println("DNS names:", cert.DNSNames)
		fmt.Println("IP addresses:", cert.IPAddresses)
		fmt.Println("Email addresses:", cert.EmailAddresses)
		fmt.Println("URIs:", cert.URIs)
		fmt.Println("Signature:", cert.Signature)
		fmt.Println("Signature algorithm:", cert.SignatureAlgorithm)
		fmt.Println("Public key algorithm:", cert.PublicKeyAlgorithm)
		fmt.Println("Public key:", cert.PublicKey)
	}
	fmt.Println(">>>>>>>>>>>>>>>> END TLS INFO <<<<<<<<<<<<<<<<")
}

func ReadLineFromConn(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)
	line, err := tp.ReadLine()
	if err != nil {
		return "", err
	}
	return line, nil
}

func CopyConn(connID int, dir bool, conn1, conn2 net.Conn) {
	buf := make([]byte, 64*1024)
	dirStr := "local -> remote"
	if dir {
		dirStr = "remote -> local"
	}
	for {
		n, err := conn1.Read(buf)
		if n > 0 {
			conn2.Write(buf[:n])
			fmt.Println()
			log.Printf("connID: %d  %s  bytes: %d\n", connID, dirStr, n)
			PrintByteArray(buf[:n])
		}
		if err != nil {
			fmt.Println()
			log.Printf("connID: %d  %s  error: %v\n", connID, dirStr, err)
			break
		}
	}
}

func PrintByteArray(bytes []byte) {
	for _, b := range bytes {
		if b >= 32 && b <= 126 {
			fmt.Printf("%c", b)
		} else if b == 9 {
			fmt.Printf("\\t")
		} else if b == 10 {
			fmt.Printf("\\n")
		} else if b == 13 {
			fmt.Printf("\\r")
		} else {
			fmt.Printf("\\x%02x", b)
		}
	}
	fmt.Println()
}
