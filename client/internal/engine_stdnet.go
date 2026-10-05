//go:build !android

package internal

import (
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

func (e *Engine) newStdNet() *stdnet.Net {
	return stdnet.NewNet(e.clientCtx, e.config.IFaceBlackList)
}
