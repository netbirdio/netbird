package main

import (
	"github.com/netbirdio/netbird/client/cmd"
	"os"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
