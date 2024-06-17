package peer

import "github.com/netbirdio/netbird/client/internal/stdnet"

func (conn *ConnectorICE) newStdNet() (*stdnet.Net, error) {
	return stdnet.NewNetWithDiscover(conn.iFaceDiscover, conn.configICE.InterfaceBlackList)
}
