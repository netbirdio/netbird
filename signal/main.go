package main

import (
	"os"

	"github.com/netbirdio/netbird/signal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
