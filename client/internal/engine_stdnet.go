//go:build !android

package internal

import (
	"github.com/pion/transport/v2/stdnet"
)

func (e *Engine) newStdNet() (*stdnet.Net, error) {
	return stdnet.NewNet()
}
