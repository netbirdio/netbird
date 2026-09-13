//go:build !darwin

package certproof

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// CollectProofs answers the certificate challenges in checks from the platform store.
// Only macOS splits the work across a user session, so every other platform reads its
// store in the daemon itself.
func CollectProofs(ctx context.Context, checks []*proto.Checks, peerKey []byte) []certposture.Proof {
	return Collect(ctx, DefaultStore(), checks, peerKey)
}
