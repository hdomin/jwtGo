package main

import (
	"net/http"

	"jwtgo/authentication"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", authentication.Login)
	mux.HandleFunc("/validate", authentication.ValidateToken)

	http.ListenAndServe(":8080", mux)
}
