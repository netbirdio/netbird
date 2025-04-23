package main

import (
	"log"

	"github.com/netbirdio/netbird/upload-server/server"
	"github.com/netbirdio/netbird/util"
)

func main() {
	util.InitLog("info", "console")

	srv := server.NewServer()
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
