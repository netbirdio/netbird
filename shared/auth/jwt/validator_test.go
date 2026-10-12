package jwt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ecdsaJWK builds a JWK for pub using uncompressed-point encoding
func ecdsaJWK(t *testing.T, kid string, pub *ecdsa.PublicKey, crv string, size int) JSONWebKey {
	t.Helper()

	point, err := pub.Bytes()
	require.NoError(t, err)
	require.Len(t, point, 1+2*size)
	require.Equal(t, byte(4), point[0], "expected uncompressed point")

	return JSONWebKey{
		Kty: "EC",
		Kid: kid,
		Use: "sig",
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(point[1 : 1+size]),
		Y:   base64.RawURLEncoding.EncodeToString(point[1+size:]),
	}
}

func TestGetPublicKeyFromECDSA_RoundTrip(t *testing.T) {
	tests := []struct {
		crv   string
		curve elliptic.Curve
		size  int
	}{
		{p256, elliptic.P256(), 32},
		{p384, elliptic.P384(), 48},
		{p521, elliptic.P521(), 66},
	}

	for _, tc := range tests {
		t.Run(tc.crv, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			got, err := getPublicKeyFromECDSA(ecdsaJWK(t, "kid", &priv.PublicKey, tc.crv, tc.size))
			require.NoError(t, err)
			assert.True(t, priv.PublicKey.Equal(got), "parsed key differs from the original")
		})
	}
}

// TestGetPublicKeyFromECDSA_ShortCoordinate covers IdPs that strip leading zero
// bytes from a coordinate instead of padding to the curve's field size.
func TestGetPublicKeyFromECDSA_ShortCoordinate(t *testing.T) {
	var (
		priv  *ecdsa.PrivateKey
		point []byte
	)
	for i := 0; i < 10000; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		p, err := key.PublicKey.Bytes()
		require.NoError(t, err)

		if p[1] == 0 || p[33] == 0 {
			priv, point = key, p
			break
		}
	}
	require.NotNil(t, priv, "no key with a leading zero coordinate byte was generated")

	jwk := JSONWebKey{
		Kty: "EC",
		Kid: "kid",
		Crv: p256,
		X:   base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(point[1:33], "\x00")),
		Y:   base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(point[33:], "\x00")),
	}

	got, err := getPublicKeyFromECDSA(jwk)
	require.NoError(t, err)
	assert.True(t, priv.PublicKey.Equal(got))
}

func TestGetPublicKeyFromECDSA_Invalid(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	valid := ecdsaJWK(t, "kid", &priv.PublicKey, p256, 32)

	offCurve := valid
	x, err := base64.RawURLEncoding.DecodeString(valid.X)
	require.NoError(t, err)
	x[31] ^= 0xff
	offCurve.X = base64.RawURLEncoding.EncodeToString(x)

	// 33 non-zero bytes is 264 bits, past P-256's 256-bit field.
	oversized := valid
	oversized.X = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 33))

	// P-521 coordinates occupy 66 bytes but only 521 bits, so a full 66-byte
	// 0xff value (528 bits) is over the field size without being over the byte
	// length. Only a bit-length bound catches this.
	overP521 := JSONWebKey{
		Kty: "EC",
		Crv: p521,
		X:   base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 66)),
		Y:   base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 66)),
	}

	zeroPoint := valid
	zeroPoint.X = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	zeroPoint.Y = base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	tests := []struct {
		name        string
		jwk         JSONWebKey
		errContains string
	}{
		{name: "missing crv", jwk: JSONWebKey{Kty: "EC", X: valid.X, Y: valid.Y}},
		{name: "missing x", jwk: JSONWebKey{Kty: "EC", Crv: p256, Y: valid.Y}},
		{name: "unsupported curve", jwk: JSONWebKey{Kty: "EC", Crv: "P-224", X: valid.X, Y: valid.Y}, errContains: "unsupported elliptic curve"},
		{name: "undecodable x", jwk: JSONWebKey{Kty: "EC", Crv: p256, X: "!!not base64!!!", Y: valid.Y}, errContains: "decode ecdsa x coordinate"},
		{name: "coordinate over field size", jwk: oversized, errContains: "exceeds curve P-256 field size of 256 bits"},
		{name: "p521 coordinate over field size", jwk: overP521, errContains: "exceeds curve P-521 field size of 521 bits"},
		{name: "off-curve point", jwk: offCurve, errContains: "parse ecdsa public key"},
		{name: "point at infinity", jwk: zeroPoint, errContains: "parse ecdsa public key"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := getPublicKeyFromECDSA(tc.jwk)
			require.Error(t, err)
			assert.Nil(t, key)
			if tc.errContains != "" {
				assert.ErrorContains(t, err, tc.errContains)
			}
		})
	}
}

// TestValidateAndParse_ECDSA verifies an ES256-signed token end to end, proving
// the parsed key actually validates signatures.
func TestValidateAndParse_ECDSA(t *testing.T) {
	const (
		kid      = "es256-kid"
		issuer   = "https://issuer.example.com/"
		audience = "netbird"
	)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwks, err := json.Marshal(Jwks{Keys: []JSONWebKey{ecdsaJWK(t, kid, &priv.PublicKey, p256, 32)}})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer srv.Close()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"sub": "user-1",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = kid

	signed, err := token.SignedString(priv)
	require.NoError(t, err)

	v := NewValidator(issuer, []string{audience}, srv.URL, false)

	parsed, err := v.ValidateAndParse(context.Background(), signed)
	require.NoError(t, err)
	require.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "user-1", claims["sub"])

	// A token signed by a different key of the same curve must be rejected.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	forged := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"sub": "user-1",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	forged.Header["kid"] = kid

	forgedSigned, err := forged.SignedString(other)
	require.NoError(t, err)

	_, err = v.ValidateAndParse(context.Background(), forgedSigned)
	require.Error(t, err)
}
