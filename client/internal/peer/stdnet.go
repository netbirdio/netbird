//go:build !android

package peer

import (
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/route"
)

func (conn *Conn) newStdNet(routes route.HAMap) (*stdnet.Net, error) {
	return stdnet.NewNet(conn.config.InterfaceBlackList, routes)
}
