package server

import (
	"net/http"
	"time"
)

// NewServer creates and configures an HTTP server.
func NewServer(handler http.Handler, port string) *http.Server {
	return &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}
