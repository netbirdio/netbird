package grpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestLoginAuthPubKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name string
		req  *proto.LoginRequest
		want string
	}{
		{"valid key", &proto.LoginRequest{PeerKeys: &proto.PeerKeys{AuthPubKey: pub}}, base64.StdEncoding.EncodeToString(pub)},
		{"legacy peer without key", &proto.LoginRequest{PeerKeys: &proto.PeerKeys{}}, ""},
		{"no peer keys", &proto.LoginRequest{}, ""},
		{"malformed key", &proto.LoginRequest{PeerKeys: &proto.PeerKeys{AuthPubKey: pub[:16]}}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, loginAuthPubKey(tc.req), "stored auth key")
		})
	}
}
