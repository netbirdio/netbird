package bind

import (
	wireguard "golang.zx2c4.com/wireguard/conn"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// TODO: This is most likely obsolete since the control fns should be called by the wrapped udpconn (ice_bind.go)
func init() {
	listener := nbnet.NewListener()
	if listener.ListenConfig.Control != nil {
		*wireguard.ControlFns = append(*wireguard.ControlFns, listener.ListenConfig.Control)
	}
}
