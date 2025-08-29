package main

import (
	"github.com/netbirdio/netbird/management/cmd"
	"os"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
