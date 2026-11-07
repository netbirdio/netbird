package peerauth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// opensslKeyPEM was written by `openssl genpkey -algorithm ed25519`, the documented way to create
// Management's signing key.
const opensslKeyPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA5nRdTx3a75pWVM+BenOvuWHyxI7/x3KUAQgz+mvdYG
-----END PRIVATE KEY-----
`

func TestParseSigningKeyPEM(t *testing.T) {
	t.Run("openssl key", func(t *testing.T) {
		key, err := ParseSigningKeyPEM([]byte(opensslKeyPEM))
		require.NoError(t, err)
		assert.Len(t, key, ed25519.PrivateKeySize, "an openssl Ed25519 key must parse")
	})

	t.Run("round trip", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		data, err := MarshalSigningKeyPEM(priv)
		require.NoError(t, err)
		key, err := ParseSigningKeyPEM(data)
		require.NoError(t, err)
		assert.Equal(t, priv, key, "the parsed key must be the encoded key")
	})

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for name, data := range map[string][]byte{
		"not PEM":          []byte("not a key"),
		"wrong block type": pkcs8PEM(t, "PUBLIC KEY", edKey),
		"not PKCS#8":       pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: []byte("junk")}),
		"not Ed25519":      pkcs8PEM(t, pemTypePrivateKey, ecKey),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseSigningKeyPEM(data)
			assert.Error(t, err, "only a PEM PKCS#8 Ed25519 private key may be accepted")
		})
	}
}

func pkcs8PEM(t *testing.T, blockType string, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func TestParsePublicKeys(t *testing.T) {
	oldPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	b64 := base64.StdEncoding.EncodeToString

	keys, err := ParsePublicKeys([]string{b64(oldPub), b64(newPub)})
	require.NoError(t, err)
	assert.Equal(t, map[KeyID]ed25519.PublicKey{Ed25519KeyID(oldPub): oldPub, Ed25519KeyID(newPub): newPub}, keys.Ed25519,
		"both keys of a rotation must be accepted, each under its derived id")

	for name, in := range map[string][]string{
		"not base64": {"not base64!"},
		"wrong size": {b64([]byte("short"))},
		"duplicate":  {b64(oldPub), b64(oldPub)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParsePublicKeys(in)
			assert.Error(t, err, "an unusable public key list must be refused")
		})
	}
}
