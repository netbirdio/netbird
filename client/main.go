package main

import (
	"os"

	"github.com/wiretrustee/wiretrustee/client/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
