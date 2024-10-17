//go:build !android

package guard

import (
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

func newStdNet(_ stdnet.ExternalIFaceDiscover, ifaceBlacklist []string) (*stdnet.Net, error) {
	return stdnet.NewNet(ifaceBlacklist)
}
