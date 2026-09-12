package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// x5cCertificate builds a self-signed certificate for the given public key and
// returns it base64-encoded as it would appear in a JWKS "x5c" entry (RFC 7517
// §4.7: standard base64 of the DER certificate).
func x5cCertificate(t *testing.T, pub crypto.PublicKey, signer crypto.Signer) string {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "netbird-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, signer)
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(der)
}

// TestValidateAndParse_ECDSA_X5c reproduces #5302: an EC/ES256 signing key whose
// JWKS entry carries an x5c certificate must still validate tokens end to end.
func TestValidateAndParse_ECDSA_X5c(t *testing.T) {
	const (
		kid      = "es256-x5c-kid"
		issuer   = "https://issuer.example.com/"
		audience = "netbird"
	)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key := ecdsaJWK(t, kid, &priv.PublicKey, p256, 32)
	key.X5c = []string{x5cCertificate(t, &priv.PublicKey, priv)}

	jwks, err := json.Marshal(Jwks{Keys: []JSONWebKey{key}})
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
}

// TestGetPublicKey_X5c covers the certificate-backed key paths. The certificate's
// key type must match the JWK kty, x5c supports only the same key types as the
// non-x5c path (RSA and EC), and mismatched or unsupported entries fail rather
// than silently broadening the accepted key types.
func TestGetPublicKey_X5c(t *testing.T) {
	const kid = "x5c-kid"

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ec384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecCert := x5cCertificate(t, &ecPriv.PublicKey, ecPriv)
	ec384Cert := x5cCertificate(t, &ec384Priv.PublicKey, ec384Priv)
	rsaCert := x5cCertificate(t, &rsaPriv.PublicKey, rsaPriv)

	tokenWithKid := func() *jwt.Token {
		tok := jwt.New(jwt.SigningMethodES256)
		tok.Header["kid"] = kid
		return tok
	}

	// A: EC kty with a matching-curve EC certificate yields the ECDSA key.
	t.Run("ec kty with ec certificate", func(t *testing.T) {
		key, err := getPublicKey(tokenWithKid(), &Jwks{Keys: []JSONWebKey{{
			Kty: "EC", Kid: kid, Crv: p256, X5c: []string{ecCert},
		}}})
		require.NoError(t, err)

		got, ok := key.(*ecdsa.PublicKey)
		require.True(t, ok, "expected *ecdsa.PublicKey, got %T", key)
		assert.True(t, ecPriv.PublicKey.Equal(got))
	})

	// B: RSA kty with an RSA certificate yields the RSA key.
	t.Run("rsa kty with rsa certificate", func(t *testing.T) {
		key, err := getPublicKey(tokenWithKid(), &Jwks{Keys: []JSONWebKey{{
			Kty: "RSA", Kid: kid, X5c: []string{rsaCert},
		}}})
		require.NoError(t, err)

		got, ok := key.(*rsa.PublicKey)
		require.True(t, ok, "expected *rsa.PublicKey, got %T", key)
		assert.True(t, rsaPriv.PublicKey.Equal(got))
	})

	// C: a malformed certificate fails cleanly.
	t.Run("malformed x5c", func(t *testing.T) {
		key, err := getPublicKey(tokenWithKid(), &Jwks{Keys: []JSONWebKey{{
			Kty: "EC", Kid: kid, X5c: []string{"not-a-valid-certificate"},
		}}})
		require.Error(t, err)
		assert.Nil(t, key)
	})

	// D: EC kty with an RSA certificate is rejected.
	t.Run("ec kty with rsa certificate", func(t *testing.T) {
		key, err := getPublicKey(tokenWithKid(), &Jwks{Keys: []JSONWebKey{{
			Kty: "EC", Kid: kid, X5c: []string{rsaCert},
		}}})
		require.Error(t, err)
		assert.Nil(t, key)
		assert.ErrorContains(t, err, "ECDSA public key")
	})

	// E: RSA kty with an EC certificate is rejected.
	t.Run("rsa kty with ec certificate", func(t *testing.T) {
		key, err := getPublicKey(tokenWithKid(), &Jwks{Keys: []JSONWebKey{{
			Kty: "RSA", Kid: kid, X5c: []string{ecCert},
		}}})
		require.Error(t, err)
		assert.Nil(t, key)
		assert.ErrorContains(t, err, "RSA public key")
	})

	// F: a kty neither RSA nor EC stays unsupported, and reports why rather than
	// looking like a missing key (which would trigger a pointless JWKS refresh).
	t.Run("unsupported kty stays unsupported", func(t *testing.T) {
		key, err := getPublicKey(tokenWithKid(), &Jwks{Keys: []JSONWebKey{{
			Kty: "OKP", Kid: kid, X5c: []string{ecCert},
		}}})
		require.Error(t, err)
		assert.Nil(t, key)
		assert.NotErrorIs(t, err, errKeyNotFound)
		assert.ErrorContains(t, err, "unsupported JWK key type")
	})

	// G: the certificate's curve must match the curve the JWK declares.
	t.Run("ec certificate curve must match jwk crv", func(t *testing.T) {
		key, err := getPublicKey(tokenWithKid(), &Jwks{Keys: []JSONWebKey{{
			Kty: "EC", Kid: kid, Crv: p256, X5c: []string{ec384Cert},
		}}})
		require.Error(t, err)
		assert.Nil(t, key)
		assert.ErrorContains(t, err, "does not match JWK curve")
	})
}
