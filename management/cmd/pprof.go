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
		return "localhost:6060"
	}
	return listenAddr
}

func pprof(listenAddr string) {
	log.Infof("listening pprof on: %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("pprof server: %v", err)
	}
}
