package peer

import "github.com/netbirdio/netbird/client/internal/stdnet"

func (conn *Conn) newStdNet() (*stdnet.Net, error) {
	return stdnet.NewNetWithDiscover(conn.iFaceDiscover, conn.config.InterfaceBlackList)
}
