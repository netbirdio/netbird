package bind

import (
	wireguard "golang.zx2c4.com/wireguard/conn"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func init() {
	// ControlFns is not thread safe and should only be modified during init.
	*wireguard.ControlFns = append(*wireguard.ControlFns, nbnet.ControlProtectSocket)
}
