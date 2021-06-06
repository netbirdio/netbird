// +build linux darwin

package iface

import (
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"net"
)

// createIface creates a tun device
func createIface(iface string, defaultMTU int) (tun.Device, error) {
	return tun.CreateTUN(iface, defaultMTU)
}

// getUAPI returns a Listener
func getUAPI(iface string) (net.Listener, error) {
	tunSock, err := ipc.UAPIOpen(iface)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(iface, tunSock)
}
