package main

import (
	"github.com/wiretrustee/wiretrustee/client/cmd"
	"os"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
