package peer

import (
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/route"
)

func (conn *Conn) newStdNet(haMap route.HAMap) (*stdnet.Net, error) {
	return stdnet.NewNetWithDiscover(conn.iFaceDiscover, conn.config.InterfaceBlackList)
}
