package proxy

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
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

func CopyConn(connID int, dir bool, conn1, conn2 net.Conn, stdoutMutex *sync.Mutex) {
	buf := make([]byte, 64*1024)
	dirStr := "local -> remote"
	if dir {
		dirStr = "remote -> local"
	}
	for {
		n, err := conn1.Read(buf)
		if n > 0 {
			conn2.Write(buf[:n])
			stdoutMutex.Lock()
			fmt.Println()
			log.Printf("connID: %d  %s  bytes: %d\n", connID, dirStr, n)
			PrintByteArray(buf[:n])
			stdoutMutex.Unlock()
		}
		if err != nil {
			stdoutMutex.Lock()
			fmt.Println()
			log.Printf("connID: %d  %s  error: %v\n", connID, dirStr, err)
			stdoutMutex.Unlock()
			break
		}
	}
}

func PrintByteArray(bytes []byte) {
	offset := 0
	base := 0
	index := 0
	for n := len(bytes); n > 0; offset, base = 0, base+16 {
		parts := []string{fmt.Sprintf("%08x:", base)}
		count := 16 - offset
		if count > n {
			count = n
		}
		ch := make([]byte, 17)
		ch[0] = ' '
		for i := 1; i <= offset; i++ {
			parts = append(parts, "  ")
			ch[i] = byte(' ')
		}
		for i := 0; i < count; i++ {
			c := bytes[index+i]
			parts = append(parts, fmt.Sprintf("%02x", c))
			if c < 32 || c >= 127 {
				c = byte('.')
			}
			ch[1+i+offset] = c
		}
		for i := offset + count; i < 16; i++ {
			parts = append(parts, "  ")
		}
		parts = append(parts, string(ch[:1+offset+count]))
		fmt.Println(strings.Join(parts, " "))
		index += count
		n -= count
	}
}
