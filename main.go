package main

import (
	"github.com/hdomin/jwtGo/authentication"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", authentication.Login)
	mux.HandleFunc("/validate", authentication.ValidateToken)

	http.ListenAndServe(":8080", mux)
}
