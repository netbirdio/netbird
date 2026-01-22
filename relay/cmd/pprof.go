//go:build pprof

package cmd

import (
	"net/http"
	_ "net/http/pprof"
	"os"

	log "github.com/sirupsen/logrus"
)

func init() {
	addr := pprofAddr()
	go pprof(addr)
}

func pprofAddr() string {
	listenAddr := os.Getenv("NB_PPROF_ADDR")
	if listenAddr == "" {
		return "localhost:6969"
	}

	return listenAddr
}

func pprof(listenAddr string) {
	log.Infof("listening pprof on: %s\n", listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("Failed to start pprof: %v", err)
	}
}
