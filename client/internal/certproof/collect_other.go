//go:build !darwin && !windows

package certproof

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// CollectProofs answers the certificate challenges in checks from the PEM directory cfg
// names, joined by its PKCS#11 token when it names one. Only macOS and Windows keep
// per-user certificates out of reach of a privileged daemon, so every other platform
// reads its store in the daemon itself.
func CollectProofs(ctx context.Context, checks []*proto.Checks, peerKey []byte, cfg Config) []certposture.Proof {
	return Collect(ctx, storeWithToken(cfg), checks, peerKey)
}

// helperStore is the store the helper reads. Nothing launches a helper on these
// platforms, so it is the platform default.
func helperStore() Store {
	return DefaultStore()
}
