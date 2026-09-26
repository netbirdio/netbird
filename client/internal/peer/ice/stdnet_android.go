package ice

import (
	"context"

	"github.com/netbirdio/netbird/client/internal/stdnet"
)

func newStdNet(ctx context.Context, iFaceDiscover stdnet.ExternalIFaceDiscover, ifaceBlacklist []string) *stdnet.Net {
	return stdnet.NewNetWithDiscover(ctx, iFaceDiscover, ifaceBlacklist)
}
