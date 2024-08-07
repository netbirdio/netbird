//go:build !android

package peer

import (
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

func (w *WorkerICE) newStdNet() (*stdnet.Net, error) {
	return stdnet.NewNet(w.config.ICEConfig.InterfaceBlackList)
}
