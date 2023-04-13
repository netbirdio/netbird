package internal

import "github.com/netbirdio/netbird/client/internal/stdnet"

func (e *Engine) newStdNet() (*stdnet.Net, error) {
	return stdnet.NewNetWithDiscover(e.mobileDep.IFaceDiscover, e.config.IFaceBlackList)
}
