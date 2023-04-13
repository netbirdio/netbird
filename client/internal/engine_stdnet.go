//go:build !android

package internal

import (
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

func (e *Engine) newStdNet() (*stdnet.Net, error) {
	return stdnet.NewNet(e.config.IFaceBlackList)
}
