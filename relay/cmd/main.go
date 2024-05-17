package main

import (
	"github.com/netbirdio/netbird/util"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/server"
)

func init() {
	util.InitLog("trace", "console")
}

func main() {

	address := "0.0.0.0:1234"
	srv := server.NewServer()
	err := srv.Listen(address)
	if err != nil {
		log.Errorf("failed to bind server: %s", err)
		os.Exit(1)
	}
}
