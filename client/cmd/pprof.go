//go:build pprof

package cmd

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/instance"
)

func init() {
	startPprof = sync.OnceFunc(func() {
		go pprof(pprofAddr())
	})
}

func pprofAddr() string {
	listenAddr := os.Getenv("NB_PPROF_ADDR")
	if listenAddr == "" {
		return instance.Current().PprofAddr()
	}

	return listenAddr
}

func pprof(listenAddr string) {
	log.Infof("listening pprof on: %s\n", listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("Failed to start pprof: %v", err)
	}
}
