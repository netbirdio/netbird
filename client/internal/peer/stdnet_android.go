package peer

import "github.com/netbirdio/netbird/client/internal/stdnet"

func (w *WorkerICE) newStdNet() (*stdnet.Net, error) {
	return stdnet.NewNetWithDiscover(w.iFaceDiscover, w.config.ICEConfig.InterfaceBlackList)
}
