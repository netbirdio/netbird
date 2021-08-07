package main

import (
	"github.com/wiretrustee/wiretrustee/management/cmd"
	"os"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
