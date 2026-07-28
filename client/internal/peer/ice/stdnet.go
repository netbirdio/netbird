//go:build !android

package ice

import (
	"context"

	"github.com/netbirdio/netbird/client/internal/stdnet"
)

func newStdNet(ctx context.Context, _ stdnet.ExternalIFaceDiscover, ifaceBlacklist []string) (*stdnet.Net, error) {
	return stdnet.NewNet(ctx, ifaceBlacklist)
}
