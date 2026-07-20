package main

import (
	"net/http"
	// nolint:gosec
	_ "net/http/pprof"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/cmd"
)

func main() {
	if pprofAddr := os.Getenv("NB_PPROF_ADDR"); pprofAddr != "" {
		log.Infof("pprof enabled, listening on: %s", pprofAddr)
		go func() {
			log.Println(http.ListenAndServe(pprofAddr, nil))
		}()
	}

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
