package main

import (
	"log"

	"github.com/netbirdio/netbird/upload-server/server"
	"github.com/netbirdio/netbird/util"
)

func main() {
	err := util.InitLog("info", "console")
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	srv := server.NewServer()
	if err = srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
