package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Errorf("failed to execute command: %v", err)
		os.Exit(1)
	}
}
