package bind

import (
	"github.com/netbirdio/netbird/client/iface/wgbackend"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// TODO: This is most likely obsolete since the control fns should be called by the wrapped udpconn (ice_bind.go)
func init() {
	listener := nbnet.NewListener()
	if listener.ListenConfig.Control != nil {
		*wgbackend.ControlFns = append(*wgbackend.ControlFns, listener.ListenConfig.Control)
	}
}
