// Command patchline runs the Patchline server: webhook intake, finding
// tracking, notifications and the web UI in a single binary.
package main

import (
	"log/slog"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("PATCHLINE_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	slog.Info("patchline listening", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
