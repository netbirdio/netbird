package ipcauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestIdentityFromContext_NoPeer(t *testing.T) {
	_, ok := IdentityFromContext(context.Background())
	assert.False(t, ok, "bare context must report no identity (fail closed)")
}

func TestIdentityFromContext_WrongAuthInfo(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{})
	_, ok := IdentityFromContext(ctx)
	assert.False(t, ok, "peer without our AuthInfo must report no identity")
}

func TestIdentityFromContext_Present(t *testing.T) {
	want := Identity{UID: 1000, GID: 1000, PID: 4242, HasPID: true}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: AuthInfo{
			CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
			Identity:       want,
		},
	})

	got, ok := IdentityFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, want, got)
}

func TestIdentity_IsPrivileged(t *testing.T) {
	// Unix
	assert.True(t, Identity{UID: 0}.IsPrivileged(), "root is privileged")
	assert.False(t, Identity{UID: 1000}.IsPrivileged(), "non-root is not privileged")
	// Windows
	assert.True(t, Identity{SID: "S-1-5-21-1-2-3-1001", Elevated: true}.IsPrivileged(), "elevated admin is privileged")
	assert.True(t, Identity{SID: "S-1-5-18"}.IsPrivileged(), "LocalSystem is privileged")
	assert.False(t, Identity{SID: "S-1-5-21-1-2-3-1001"}.IsPrivileged(), "non-elevated admin is NOT privileged")
}

func TestIdentity_IsWindows(t *testing.T) {
	assert.True(t, Identity{SID: "S-1-5-18"}.IsWindows())
	assert.False(t, Identity{UID: 0}.IsWindows())
}
