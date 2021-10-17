package main

import (
	"github.com/wiretrustee/wiretrustee/client/cmd"
	"os"
)

var Version = "development"

func main() {

	cmd.Version = Version
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
