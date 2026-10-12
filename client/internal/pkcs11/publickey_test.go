package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECPublicKey(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
		oid   asn1.ObjectIdentifier
	}{
		{"P-256", elliptic.P256(), asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}},
		{"P-384", elliptic.P384(), asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
	}
	for _, tt := range curves {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)
			params, err := asn1.Marshal(tt.oid)
			require.NoError(t, err)
			point := uncompressedPoint(key)
			wrapped, err := asn1.Marshal(point)
			require.NoError(t, err)

			// PKCS#11 wraps the point in an OCTET STRING, but some modules return it bare.
			for form, encoded := range map[string][]byte{"DER octet string": wrapped, "bare point": point} {
				pub, err := ecPublicKey(params, encoded)
				require.NoError(t, err, form)
				assert.True(t, key.PublicKey.Equal(pub), "%s must decode to the generated key", form)
			}
		})
	}
}

func TestECPublicKey_Rejections(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p256, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	require.NoError(t, err)
	brainpool, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7})
	require.NoError(t, err)
	point := uncompressedPoint(key)

	_, err = ecPublicKey(brainpool, point)
	assert.Error(t, err, "curves the proof cannot use must be rejected")
	_, err = ecPublicKey(p256, point[:len(point)-1])
	assert.Error(t, err, "a truncated point must be rejected")
	_, err = ecPublicKey([]byte("junk"), point)
	assert.Error(t, err, "malformed parameters must be rejected")
}

func TestRSAPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pub, err := rsaPublicKey(key.N.Bytes(), big.NewInt(int64(key.E)).Bytes())
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(pub), "modulus and exponent must decode to the generated key")

	_, err = rsaPublicKey(key.N.Bytes(), nil)
	assert.Error(t, err, "a missing exponent must be rejected")
}

func TestULongRoundTrip(t *testing.T) {
	v, err := ulongValue(ULong(ClassPrivateKey))
	require.NoError(t, err)
	assert.Equal(t, uint(ClassPrivateKey), v)

	_, err = ulongValue([]byte{1, 2, 3})
	assert.Error(t, err, "a value of the wrong width must be rejected")
}

func uncompressedPoint(key *ecdsa.PrivateKey) []byte {
	size := (key.Curve.Params().BitSize + 7) / 8
	point := append([]byte{4}, key.X.FillBytes(make([]byte, size))...)
	return append(point, key.Y.FillBytes(make([]byte, size))...)
}
