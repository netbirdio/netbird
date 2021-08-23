package main

import (
	"github.com/matishsiao/goInfo"
	"github.com/wiretrustee/wiretrustee/client/cmd"
	"os"
)

func main() {

	gi := goInfo.GetInfo()
	gi.VarDump()

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
