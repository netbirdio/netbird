package main

import (
	"github.com/wiretrustee/wiretrustee/client/cmd"
	"os"
)

var version = "development"

func main() {

	cmd.Version = version
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
