// +build linux darwin

package iface

import (
	"golang.zx2c4.com/wireguard/ipc"
	"net"
)

// getUAPI returns a Listener
func getUAPI(iface string) (net.Listener, error) {
	tunSock, err := ipc.UAPIOpen(iface)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(iface, tunSock)
}
