package bind

import (
	wireguard "golang.zx2c4.com/wireguard/conn"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func init() {
	listener := nbnet.NewListener()
	if listener.ListenConfig.Control != nil {
		*wireguard.ControlFns = append(*wireguard.ControlFns, listener.ListenConfig.Control)
	}
}
