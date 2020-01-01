package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// HelloUser is a view that greets a user
func HelloUser(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Hello %v! \n", req.TLS.PeerCertificates[0].EmailAddresses[0])
}

func main() {
	certBytes, err := ioutil.ReadFile("../cert.pem")
	if err != nil {
		log.Fatalln("Unable to read cert.pem", err)
	}

	clientCertPool := x509.NewCertPool()
	if ok := clientCertPool.AppendCertsFromPEM(certBytes); !ok {
		log.Fatalln("Unable to add certificate to certificate pool")
	}

	tlsConfig := &tls.Config{
		// Reject any TLS certificate that cannot be validated
		ClientAuth: tls.RequireAndVerifyClientCert,
		// Ensure that we only use our "CA" to validate certificates
		ClientCAs: clientCertPool,
		// PFS because we can
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		// Force it server side
		PreferServerCipherSuites: true,
		// TLS 1.2 because we can
		MinVersion: tls.VersionTLS12,
	}

	tlsConfig.BuildNameToCertificate()

	http.HandleFunc("/", HelloUser)

	httpServer := &http.Server{
		Addr:      ":8080",
		TLSConfig: tlsConfig,
	}

	log.Println(httpServer.ListenAndServeTLS("../cert.pem", "../key.pem"))
}
