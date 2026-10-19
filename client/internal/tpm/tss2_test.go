package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/tpm/tpmtest"
)

// derEmptyAuthTrue is the explicit [0] tag around a DER BOOLEAN TRUE, as encoding/asn1
// writes emptyAuth; OpenSSL writes the same element with 0x01 as the content byte.
var (
	derEmptyAuthTrue     = []byte{0xa0, 0x03, 0x01, 0x01, 0xff}
	opensslEmptyAuthTrue = []byte{0xa0, 0x03, 0x01, 0x01, 0x01}
)

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func TestParseKey_AcceptsOpenSSLBoolean(t *testing.T) {
	key := p256(t)
	der := decodePEM(t, tpmtest.KeyPEM(t, &key.PublicKey))
	require.Equal(t, 1, bytes.Count(der, derEmptyAuthTrue), "fixture carries one DER emptyAuth TRUE")

	// The same key as tpm2-openssl and tpm2-tss-engine write it: identical apart from
	// the BOOLEAN content byte.
	openssl := bytes.Replace(der, derEmptyAuthTrue, opensslEmptyAuthTrue, 1)

	signer, err := ParseKey(openssl)
	require.NoError(t, err, "BER allows any non-zero byte for TRUE, and OpenSSL writes 0x01")
	assert.True(t, key.PublicKey.Equal(signer.Public()), "the key is the same either way")
}

func TestParseKey_AcceptsPersistentParent(t *testing.T) {
	key := p256(t)
	// 0x81000001 overflows a 32-bit int, the width the parent used to be decoded into.
	der := decodePEM(t, tpmtest.KeyPEM(t, &key.PublicKey, tpmtest.WithParent(0x81000001)))

	parsed, err := parseTSS2(der)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x81000001), parsed.Parent, "persistent parent handle")
	assert.True(t, persistentHandle(parsed.Parent), "the key is loaded under the persistent parent directly")
}

func TestParseKey_RejectsParentOutOfRange(t *testing.T) {
	key := p256(t)
	for _, parent := range []int64{-1, 0x1_0000_0000, 0x02000000} {
		_, err := parseTSS2(decodePEM(t, tpmtest.KeyPEM(t, &key.PublicKey, tpmtest.WithParent(parent))))
		assert.ErrorIs(t, err, errBadParent, "parent %#x is neither persistent nor a hierarchy", parent)
	}
}

func TestBERBoolean(t *testing.T) {
	absent, err := berBoolean(asn1.RawValue{})
	require.NoError(t, err)
	assert.False(t, absent, "an absent emptyAuth means the key needs authorization")

	for content, want := range map[byte]bool{0x00: false, 0x01: true, 0xff: true} {
		v := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagBoolean, Bytes: []byte{content}, FullBytes: []byte{0x01, 0x01, content}}
		got, err := berBoolean(v)
		require.NoError(t, err)
		assert.Equal(t, want, got, "content byte %#x", content)
	}

	_, err = berBoolean(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagInteger, Bytes: []byte{1}, FullBytes: []byte{0x02, 0x01, 0x01}})
	assert.Error(t, err, "an INTEGER is not a BOOLEAN")
}
