package main

import (
	"fmt"
	"github.com/wiretrustee/wiretrustee/cmd"
	"github.com/wiretrustee/wiretrustee/iface"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"os"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}

	intf := "wt0"

	key, err := wgtypes.ParseKey("Dju6IDLQPdjS+a1dh/DDySHFAUmW+EiaBtmTwREGyGU=")
	if err != nil {
		panic(err)
	}

	exists, err := iface.Exists(intf)
	if err != nil {
		panic(err)
	}

	if !*exists {
		err = iface.Create(intf, "10.30.30.1/24")
		if err != nil {
			panic(err)
		}
		err = iface.Configure(intf, key.String())
		if err != nil {
			panic(err)
		}
	}

	wgPort, err := iface.GetListenPort(intf)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%d", wgPort)

	select {}

}
