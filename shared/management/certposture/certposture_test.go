package certposture

import (
	"crypto"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
)

var (
	secret   = []byte("test-secret")
	peerKey  = []byte("peer-public-key-aaaaaaaaaaaaaaaa")
	otherKey = []byte("peer-public-key-bbbbbbbbbbbbbbbb")
	now      = time.Now().Truncate(Window)
)

func TestChallenger_NonceIsStableWithinWindowAndPerPeer(t *testing.T) {
	c := NewChallenger(secret)

	assert.Equal(t, c.Nonce(peerKey, now), c.Nonce(peerKey, now.Add(time.Minute)))
	assert.NotEqual(t, c.Nonce(peerKey, now), c.Nonce(peerKey, now.Add(Window)))
	assert.NotEqual(t, c.Nonce(peerKey, now), c.Nonce(otherKey, now))
	assert.NotEqual(t, c.Nonce(peerKey, now), NewChallenger([]byte("other")).Nonce(peerKey, now))
}

func TestChallenger_VerifyNonce(t *testing.T) {
	c := NewChallenger(secret)
	nonce := c.Nonce(peerKey, now)

	tests := []struct {
		name    string
		nonce   []byte
		peerKey []byte
		at      time.Time
		wantErr error
	}{
		{"current window", nonce, peerKey, now, nil},
		{"previous window still accepted", nonce, peerKey, now.Add(Window), nil},
		{"two windows later expired", nonce, peerKey, now.Add(2 * Window), ErrNonceExpired},
		{"issued in the future rejected", c.Nonce(peerKey, now.Add(Window)), peerKey, now, ErrNonceExpired},
		{"other peer", nonce, otherKey, now, ErrNonceMismatch},
		{"tampered mac", tamper(nonce, len(nonce)-1), peerKey, now, ErrNonceMismatch},
		{"malformed", nonce[:10], peerKey, now, ErrNonceMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := c.verifyNonce(tt.nonce, tt.peerKey, tt.at)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestSignVerify_RoundTripPerKeyType(t *testing.T) {
	ca := certtest.NewCA(t, "root")
	keys := map[string]crypto.Signer{
		SigAlgECDSASHA256:  certtest.ECDSAKey(t),
		SigAlgRSAPSSSHA256: certtest.RSAKey(t),
		SigAlgEd25519:      certtest.Ed25519Key(t),
	}
	for wantAlg, key := range keys {
		t.Run(wantAlg, func(t *testing.T) {
			c := NewChallenger(secret)
			proof := signedProof(t, c, ca, key)
			assert.Equal(t, wantAlg, proof.SigAlg)

			chain, err := c.Verify(proof, peerKey, now)
			require.NoError(t, err)
			require.Len(t, chain, 1)
			assert.NoError(t, VerifyChain(chain, mustPool(t, ca.PEM), now))
		})
	}
}

func TestVerify_Rejections(t *testing.T) {
	ca := certtest.NewCA(t, "root")
	c := NewChallenger(secret)
	good := signedProof(t, c, ca, certtest.ECDSAKey(t))

	tests := []struct {
		name    string
		mutate  func(p Proof) Proof
		peerKey []byte
		wantErr error
	}{
		{"replayed for other peer", identity, otherKey, ErrNonceMismatch},
		{"signature tampered", func(p Proof) Proof { p.Signature = tamper(p.Signature, 5); return p }, peerKey, ErrSignatureInvalid},
		{"nonce swapped after signing", func(p Proof) Proof { p.Nonce = c.Nonce(peerKey, now.Add(-Window)); return p }, peerKey, ErrSignatureInvalid},
		{"foreign leaf presented", func(p Proof) Proof {
			p.Chain = [][]byte{ca.Issue(t, certtest.ECDSAKey(t), "other").Raw}
			return p
		}, peerKey, ErrSignatureInvalid},
		{"alg mismatch", func(p Proof) Proof { p.SigAlg = SigAlgEd25519; return p }, peerKey, ErrSigAlgMismatch},
		{"empty chain", func(p Proof) Proof { p.Chain = nil; return p }, peerKey, ErrEmptyChain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Verify(tt.mutate(good), tt.peerKey, now)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestVerify_SecretMismatchAcrossChallengers(t *testing.T) {
	ca := certtest.NewCA(t, "root")
	proof := signedProof(t, NewChallenger(secret), ca, certtest.ECDSAKey(t))

	_, err := NewChallenger([]byte("other-instance-secret")).Verify(proof, peerKey, now)
	assert.ErrorIs(t, err, ErrNonceMismatch)
}

func TestChainMatchesCAs(t *testing.T) {
	ca := certtest.NewCA(t, "root")
	otherCA := certtest.NewCA(t, "other-root")
	leaf := ca.Issue(t, certtest.ECDSAKey(t), "device")
	chainPEM := EncodeChainPEM([]*x509.Certificate{leaf})

	assert.True(t, ChainMatchesCAs(chainPEM, []string{ca.PEM}, now))
	assert.True(t, ChainMatchesCAs(chainPEM, []string{otherCA.PEM, ca.PEM}, now))
	assert.False(t, ChainMatchesCAs(chainPEM, []string{otherCA.PEM}, now))
	assert.False(t, ChainMatchesCAs(chainPEM, []string{ca.PEM}, now.Add(30*24*time.Hour)))
	assert.False(t, ChainMatchesCAs(chainPEM, []string{"not a pem"}, now))
	assert.False(t, ChainMatchesCAs("not a pem", []string{ca.PEM}, now))
}

func TestChainPEM_RoundTrip(t *testing.T) {
	ca := certtest.NewCA(t, "root")
	leaf := ca.Issue(t, certtest.ECDSAKey(t), "device")

	chain, err := ParseChainPEM(EncodeChainPEM([]*x509.Certificate{leaf, ca.Cert}))
	require.NoError(t, err)
	require.Len(t, chain, 2)
	assert.Equal(t, leaf.Raw, chain[0].Raw)
	assert.Equal(t, ca.Cert.Raw, chain[1].Raw)
}

func signedProof(t *testing.T, c *Challenger, ca *certtest.CA, key crypto.Signer) Proof {
	t.Helper()
	leaf := ca.Issue(t, key, "device")
	nonce := c.Nonce(peerKey, now)
	sigAlg, sig, err := Sign(key, nonce, peerKey)
	require.NoError(t, err)
	return Proof{Nonce: nonce, Chain: [][]byte{leaf.Raw}, SigAlg: sigAlg, Signature: sig}
}

func mustPool(t *testing.T, pems ...string) *x509.CertPool {
	t.Helper()
	pool, err := ParseCAs(pems)
	require.NoError(t, err)
	return pool
}

func identity(p Proof) Proof { return p }

func tamper(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0xff
	return out
}
