package encryption

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newKeyPair(t testing.TB) (wgtypes.Key, wgtypes.Key) {
	t.Helper()
	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return priv, priv.PublicKey()
}

// The cache must stay wire compatible with peers that use the uncached functions,
// in both directions.
func TestSharedKeyCache_InteropWithUncached(t *testing.T) {
	alicePriv, alicePub := newKeyPair(t)
	bobPriv, bobPub := newKeyPair(t)
	alice := NewSharedKeyCache(alicePriv)
	msg := []byte("offer")

	enc, err := alice.Encrypt(msg, bobPub)
	require.NoError(t, err)
	dec, err := Decrypt(enc, alicePub, bobPriv)
	require.NoError(t, err)
	assert.Equal(t, msg, dec, "uncached peer must read a cached sender's message")

	enc, err = Encrypt(msg, alicePub, bobPriv)
	require.NoError(t, err)
	dec, err = alice.Decrypt(enc, bobPub)
	require.NoError(t, err)
	assert.Equal(t, msg, dec, "cached peer must read an uncached sender's message")
}

// Two messages to the same peer share the derived key but never the nonce, so the
// ciphertexts differ.
func TestSharedKeyCache_FreshNoncePerMessage(t *testing.T) {
	priv, _ := newKeyPair(t)
	_, peerPub := newKeyPair(t)
	c := NewSharedKeyCache(priv)

	a, err := c.Encrypt([]byte("same"), peerPub)
	require.NoError(t, err)
	b, err := c.Encrypt([]byte("same"), peerPub)
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "ciphertexts of identical plaintext must differ")
	assert.Len(t, c.keys, 1, "the shared key must be derived once per peer")
}

// A message from one peer must not decrypt under another peer's cached key.
func TestSharedKeyCache_DoesNotMixPeers(t *testing.T) {
	alicePriv, alicePub := newKeyPair(t)
	bobPriv, _ := newKeyPair(t)
	_, carolPub := newKeyPair(t)
	alice := NewSharedKeyCache(alicePriv)

	enc, err := Encrypt([]byte("hi"), alicePub, bobPriv)
	require.NoError(t, err)
	_, err = alice.Decrypt(enc, carolPub)
	assert.Error(t, err, "a message from Bob must not open with Carol's key")
}

func TestSharedKeyCache_RejectsShortMessage(t *testing.T) {
	priv, _ := newKeyPair(t)
	_, peerPub := newKeyPair(t)
	_, err := NewSharedKeyCache(priv).Decrypt(make([]byte, nonceSize-1), peerPub)
	assert.Error(t, err)
}

func TestSharedKeyCache_StaysBounded(t *testing.T) {
	priv, _ := newKeyPair(t)
	c := NewSharedKeyCache(priv)
	c.limit = 4

	for i := 0; i < 20; i++ {
		_, peerPub := newKeyPair(t)
		_, err := c.Encrypt([]byte("x"), peerPub)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(c.keys), c.limit, "cache must not grow past its cap")
	}
	assert.Len(t, c.keys, c.limit, "a full cache keeps evicting one entry per new peer")
	c.Clear()
	assert.Empty(t, c.keys, "Clear must drop every entry")
}

func TestSharedKeyCache_Concurrent(t *testing.T) {
	alicePriv, alicePub := newKeyPair(t)
	bobPriv, bobPub := newKeyPair(t)
	alice := NewSharedKeyCache(alicePriv)
	bob := NewSharedKeyCache(bobPriv)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				enc, err := alice.Encrypt([]byte("m"), bobPub)
				if !assert.NoError(t, err) {
					return
				}
				dec, err := bob.Decrypt(enc, alicePub)
				if !assert.NoError(t, err) || !assert.Equal(t, []byte("m"), dec) {
					return
				}
			}
		}()
	}
	wg.Wait()
}

func BenchmarkEncryptDecryptUncached(b *testing.B) {
	alicePriv, alicePub := newKeyPair(b)
	bobPriv, bobPub := newKeyPair(b)
	msg := make([]byte, 512)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		enc, err := Encrypt(msg, bobPub, alicePriv)
		require.NoError(b, err)
		_, err = Decrypt(enc, alicePub, bobPriv)
		require.NoError(b, err)
	}
}

func BenchmarkEncryptDecryptCached(b *testing.B) {
	alicePriv, alicePub := newKeyPair(b)
	bobPriv, bobPub := newKeyPair(b)
	alice := NewSharedKeyCache(alicePriv)
	bob := NewSharedKeyCache(bobPriv)
	msg := make([]byte, 512)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		enc, err := alice.Encrypt(msg, bobPub)
		require.NoError(b, err)
		_, err = bob.Decrypt(enc, alicePub)
		require.NoError(b, err)
	}
}
