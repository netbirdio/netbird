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

func TestIdentity_String(t *testing.T) {
	assert.Equal(t, "uid=1000 gid=1000 pid=42", Identity{UID: 1000, GID: 1000, PID: 42, HasPID: true}.String())
	assert.Equal(t, "uid=1000 gid=1000", Identity{UID: 1000, GID: 1000}.String())
	assert.Equal(t, "sid=S-1-5-21-1 pid=42", Identity{SID: "S-1-5-21-1", PID: 42, HasPID: true}.String())
	assert.Equal(t, "sid=S-1-5-21-1", Identity{SID: "S-1-5-21-1"}.String())
}

func TestIdentity_IsWindows(t *testing.T) {
	assert.True(t, Identity{SID: "S-1-5-18"}.IsWindows())
	assert.False(t, Identity{UID: 0}.IsWindows())
}
