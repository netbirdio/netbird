package certproof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
)

func TestBuildChain_FollowsIssuersThroughThePool(t *testing.T) {
	root := certtest.NewCA(t, "root")
	intermediate := certtest.NewIntermediate(t, root, "intermediate")
	unrelated := certtest.NewCA(t, "unrelated")
	leaf := intermediate.Issue(t, certtest.ECDSAKey(t), "device")
	pool := []*x509.Certificate{unrelated.Cert, root.Cert, leaf, intermediate.Cert}

	chain := buildChain(leaf, pool)

	require.Equal(t, []*x509.Certificate{leaf, intermediate.Cert, root.Cert}, chain)
	roots, err := certposture.ParseCAs([]string{root.PEM})
	require.NoError(t, err)
	assert.NoError(t, certposture.VerifyChain(chain, roots, time.Now()))
}

func TestBuildChain_StopsWhereThePoolEnds(t *testing.T) {
	root := certtest.NewCA(t, "root")
	intermediate := certtest.NewIntermediate(t, root, "intermediate")
	leaf := intermediate.Issue(t, certtest.ECDSAKey(t), "device")

	assert.Equal(t, []*x509.Certificate{leaf}, buildChain(leaf, nil))
	assert.Equal(t, []*x509.Certificate{leaf, intermediate.Cert}, buildChain(leaf, []*x509.Certificate{intermediate.Cert}))
}

func TestSchemeFor(t *testing.T) {
	ecKey := certtest.ECDSAKey(t)
	rsaKey := certtest.RSAKey(t)
	pss := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}

	tests := []struct {
		name string
		pub  crypto.PublicKey
		opts crypto.SignerOpts
		want sigScheme
	}{
		{"ecdsa sha256", ecKey.Public(), crypto.SHA256, schemeECDSASHA256},
		{"ecdsa sha384", ecKey.Public(), crypto.SHA384, schemeECDSASHA384},
		{"rsa pss sha256", rsaKey.Public(), pss, schemeRSAPSSSHA256},
		{"rsa pkcs1v15", rsaKey.Public(), crypto.SHA256, 0},
		{"ed25519", certtest.Ed25519Key(t).Public(), crypto.Hash(0), 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := schemeFor(tc.pub, tc.opts)
			if tc.want == 0 {
				assert.ErrorIs(t, err, errUnsupportedScheme)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestECDSASignatureASN1(t *testing.T) {
	key := certtest.ECDSAKey(t).(*ecdsa.PrivateKey)
	digest := sha256.Sum256([]byte("nonce"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)
	raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)

	der, err := ecdsaSignatureASN1(raw)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], der))

	_, err = ecdsaSignatureASN1(raw[:63])
	assert.Error(t, err)
}
