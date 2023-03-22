//go:build !android

package peer

import (
	"github.com/pion/transport/v2/stdnet"
)

func (conn *Conn) newStdNet() (*stdnet.Net, error) {
	return stdnet.NewNet()
}
