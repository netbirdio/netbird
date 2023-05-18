package main

import (
	"os"

	"github.com/netbirdio/netbird/client/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
