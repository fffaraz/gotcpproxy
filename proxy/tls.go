package proxy

import (
	"crypto/tls"
	"fmt"
)

func PrintTLSConnState(conn *tls.Conn) {
	fmt.Println(">>>>>>>>>>>>>>>> TLS INFO <<<<<<<<<<<<<<<<")
	state := conn.ConnectionState()
	fmt.Println("Version:", state.Version)
	fmt.Println("HandshakeComplete:", state.HandshakeComplete)
	fmt.Println("DidResume:", state.DidResume)
	fmt.Println("CipherSuite:", state.CipherSuite)
	fmt.Println("NegotiatedProtocol:", state.NegotiatedProtocol)
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
