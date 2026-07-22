package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer = "https://idp.example.com"
	testKid    = "test-key-1"
)

var testAudience = []string{"netbird"}

// newTestValidator returns a Validator whose key set contains the public part of
// the returned RSA key, so tokens signed with that key can be validated without
// any HTTP round-trip.
func newTestValidator(t *testing.T) (*Validator, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk := JSONWebKey{
		Kty: "RSA",
		Kid: testKid,
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}

	v := &Validator{
		keys:         &Jwks{Keys: []JSONWebKey{jwk}},
		issuer:       testIssuer,
		audienceList: testAudience,
	}
	return v, key
}

// signToken builds and signs a token. iatNbfOffset is applied to the iat/nbf
// claims (a positive value places them in the future, simulating an IdP whose
// clock is ahead of the validator); expFromNow sets the exp claim relative to
// now (a negative value yields an expired token). kid is stamped into the token
// header, and the token is signed with the provided key, so callers can
// exercise both the unknown-kid path (kid not in the key set) and the
// wrong-signature path (kid known but signed with a different key).
func signToken(t *testing.T, key *rsa.PrivateKey, kid string, iatNbfOffset, expFromNow time.Duration) string {
	t.Helper()

	issued := time.Now().Add(iatNbfOffset)
	claims := jwt.MapClaims{
		"iss": testIssuer,
		"aud": testAudience,
		"iat": issued.Unix(),
		"nbf": issued.Unix(),
		"exp": time.Now().Add(expFromNow).Unix(),
		"sub": "user-123",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func TestValidateAndParse(t *testing.T) {
	tests := []struct {
		name         string
		kid          string
		iatNbfOffset time.Duration
		expFromNow   time.Duration
		wrongKey     bool
		wantErr      bool
	}{
		{
			name:         "issuer ahead, within leeway",
			kid:          testKid,
			iatNbfOffset: defaultClockSkewLeeway / 2,
			expFromNow:   time.Hour,
		},
		{
			name:         "issuer ahead, beyond leeway",
			kid:          testKid,
			iatNbfOffset: defaultClockSkewLeeway * 3 / 2,
			expFromNow:   time.Hour,
			wantErr:      true,
		},
		{
			name:       "expired beyond leeway",
			kid:        testKid,
			expFromNow: -defaultClockSkewLeeway * 2,
			wantErr:    true,
		},
		{
			name:       "unknown kid",
			kid:        "unknown-kid",
			expFromNow: time.Hour,
			wantErr:    true,
		},
		{
			name:       "known kid, wrong signature",
			kid:        testKid,
			expFromNow: time.Hour,
			wrongKey:   true,
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, key := newTestValidator(t)
			if tc.wrongKey {
				other, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				key = other
			}

			token := signToken(t, key, tc.kid, tc.iatNbfOffset, tc.expFromNow)

			parsed, err := v.ValidateAndParse(context.Background(), token)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.True(t, parsed.Valid)
		})
	}
}
