package ice

import "github.com/netbirdio/netbird/client/internal/stdnet"

func newStdNet(iFaceDiscover stdnet.ExternalIFaceDiscover, ifaceBlacklist []string) (*stdnet.Net, error) {
	return stdnet.NewNetWithDiscover(iFaceDiscover, ifaceBlacklist)
}
