package server

import (
	"net/http"
	"time"
)

// NewServer creates and configures an HTTP server.
func NewServer(mux *http.ServeMux, port string) *http.Server {
	return &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}

