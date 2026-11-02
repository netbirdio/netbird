package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/peerauth"
)

func TestPeerAuthTokenKeys(t *testing.T) {
	t.Run("no public keys", func(t *testing.T) {
		keys, err := peerAuthTokenKeys(&Config{AuthSecret: "relay-secret"})
		require.NoError(t, err)
		assert.Empty(t, keys.Ed25519, "without public keys no bound token may verify, whatever the auth secret")
	})

	t.Run("public keys", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		keys, err := peerAuthTokenKeys(&Config{PeerAuthPublicKeys: []string{base64.StdEncoding.EncodeToString(pub)}})
		require.NoError(t, err)
		require.NoError(t, keys.Validate())
		assert.Equal(t, pub, keys.Ed25519[peerauth.Ed25519KeyID(pub)], "the configured key must verify bound tokens")
	})

	t.Run("malformed public key", func(t *testing.T) {
		_, err := peerAuthTokenKeys(&Config{PeerAuthPublicKeys: []string{"bm90LWEta2V5"}})
		assert.Error(t, err, "a malformed public key must fail startup")
	})
}
