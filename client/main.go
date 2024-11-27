package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/cmd"
)

func main() {
	if err := os.Setenv("NB_LOG_MAX_SIZE_MB", "100"); err != nil {
		log.Errorf("Failed setting log-size: %v", err)
	}
	if err := os.Setenv("NB_WINDOWS_PANIC_LOG", filepath.Join(os.Getenv("ProgramData"), "netbird", "netbird.err")); err != nil {
		log.Errorf("Failed setting panic log path: %v", err)
	}

	go startPprofServer()

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func startPprofServer() {
	pprofAddr := "localhost:6969"
	log.Infof("Starting pprof debugging server on %s", pprofAddr)
	if err := http.ListenAndServe(pprofAddr, nil); err != nil {
		log.Infof("pprof server failed: %v", err)
	}
}
