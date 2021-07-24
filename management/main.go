package main

import (
	cmd2 "github.com/wiretrustee/wiretrustee/management/cmd"
	"os"
)

func main() {
	if err := cmd2.Execute(); err != nil {
		os.Exit(1)
	}
}
