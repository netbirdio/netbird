package main

import (
	cmd "github.com/wiretrustee/wiretrustee/management/impl"
	"os"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
