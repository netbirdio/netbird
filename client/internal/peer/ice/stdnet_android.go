package ice

import (
	"context"

	"github.com/netbirdio/netbird/client/internal/stdnet"
)

func newStdNet(ctx context.Context, iFaceDiscover stdnet.ExternalIFaceDiscover, ifaceBlacklist []string, detector *stdnet.WGDetector) (*stdnet.Net, error) {
	return stdnet.NewNetWithDiscover(ctx, iFaceDiscover, ifaceBlacklist, detector)
}
