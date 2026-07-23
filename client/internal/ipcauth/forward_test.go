package ipcauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestForwardIdentityRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
	}{
		{"unix uid/gid", Identity{UID: 1000, GID: 1000}},
		{"windows sid+groups+elevated", Identity{
			SID:      "S-1-5-21-1-2-3-1001",
			Groups:   []string{"S-1-5-32-544", "S-1-1-0"},
			Elevated: true,
		}},
		{"windows sid only", Identity{SID: "S-1-5-21-9"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), ForwardIdentityMetadata(tc.id))
			got, ok := forwardedIdentity(ctx)
			assert.True(t, ok)
			assert.Equal(t, tc.id, got)
		})
	}
}

func TestForwardedIdentity_None(t *testing.T) {
	_, ok := forwardedIdentity(context.Background())
	assert.False(t, ok, "no metadata → no forwarded identity")

	// Empty metadata (no forwarding keys) → none.
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("other", "x"))
	_, ok = forwardedIdentity(ctx)
	assert.False(t, ok)
}
