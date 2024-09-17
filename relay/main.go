package main

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatalf("failed to execute command: %v", err)
	}
}
