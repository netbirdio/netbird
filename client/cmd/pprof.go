//go:build pprof

package cmd

import (
	"net/http"
	_ "net/http/pprof"
	"os"

	log "github.com/sirupsen/logrus"
)

func init() {
	if addr, ok := isPprofAddr(); ok {
		go pprof(addr)
	} else {
		go pprof("localhost:6969")
	}
}

func isPprofAddr() (string, bool) {
	listenAddr := os.Getenv("NB_PPROF_ADDR")
	if listenAddr == "" {
		return "", false
	}

	return listenAddr, true
}

func pprof(listenAddr string) {
	log.Infof("listening pprof on: %s\n", listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("Failed to start pprof: %v", err)
	}
}
