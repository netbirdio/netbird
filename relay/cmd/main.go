package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/util"
)

func init() {
	util.InitLog("trace", "console")
}

func waitForExitSignal() {
	osSigs := make(chan os.Signal, 1)
	signal.Notify(osSigs, syscall.SIGINT, syscall.SIGTERM)
	_ = <-osSigs
}

func main() {
	address := "10.145.236.1:1235"
	srv := server.NewServer()
	err := srv.Listen(address)
	if err != nil {
		log.Errorf("failed to bind server: %s", err)
		os.Exit(1)
	}

	waitForExitSignal()

	err = srv.Close()
	if err != nil {
		log.Errorf("failed to close server: %s", err)
		os.Exit(1)
	}
}
