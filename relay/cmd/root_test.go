package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/peerauth"
)

func TestPeerAuthTokenKeys(t *testing.T) {
	secret := sha256.Sum256([]byte("relay-secret"))

	t.Run("secret only", func(t *testing.T) {
		keys, err := peerAuthTokenKeys(&Config{}, secret[:])
		require.NoError(t, err)
		mode, err := keys.Mode()
		require.NoError(t, err)
		assert.Equal(t, peerauth.AlgoHMACSHA256, mode, "without public keys bound tokens are verified with the secret")
	})

	t.Run("public keys replace the secret", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		keys, err := peerAuthTokenKeys(&Config{PeerAuthPublicKeys: []string{base64.StdEncoding.EncodeToString(pub)}}, secret[:])
		require.NoError(t, err)
		mode, err := keys.Mode()
		require.NoError(t, err)
		assert.Equal(t, peerauth.AlgoEd25519, mode, "configured public keys must select Ed25519")
		assert.Empty(t, keys.HMAC, "the secret must not verify bound tokens once public keys are set")
	})

	t.Run("malformed public key", func(t *testing.T) {
		_, err := peerAuthTokenKeys(&Config{PeerAuthPublicKeys: []string{"bm90LWEta2V5"}}, secret[:])
		assert.Error(t, err, "a malformed public key must fail startup")
	})
}
