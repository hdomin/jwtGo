package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"jwtgo/authentication"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", authentication.Login)
	mux.HandleFunc("/validate", authentication.ValidateToken)

	certFile := "./keys/cert.pem"
	keyFile := "./keys/key.pem"

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
		TLSConfig: &tls.Config{
			// Load the SSL/TLS certificate and private key
			Certificates: []tls.Certificate{},
		},
	}

	err := server.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}

}
