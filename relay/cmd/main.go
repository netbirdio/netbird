package main

import (
	"os"

	"github.com/netbirdio/netbird/util"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/server"
)

func init() {
	util.InitLog("trace", "console")
}

func main() {

	address := "10.145.236.1:1235"
	srv := server.NewServer()
	err := srv.Listen(address)
	if err != nil {
		log.Errorf("failed to bind server: %s", err)
		os.Exit(1)
	}

	select {}
}
