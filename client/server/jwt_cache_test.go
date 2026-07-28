package server

import (
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestJWTCacheGetValidatesTokenClaims(t *testing.T) {
	now := time.Now()
	testCases := []struct {
		name  string
		ttl   time.Duration
		claim gojwt.MapClaims
		valid bool
	}{
		{
			name: "valid token within iat ttl",
			ttl:  time.Minute,
			claim: gojwt.MapClaims{
				"iat": now.Add(-30 * time.Second).Unix(),
				"exp": now.Add(time.Hour).Unix(),
			},
			valid: true,
		},
		{
			name: "expired exp claim",
			ttl:  time.Hour,
			claim: gojwt.MapClaims{
				"iat": now.Add(-30 * time.Second).Unix(),
				"exp": now.Add(-time.Second).Unix(),
			},
		},
		{
			name: "iat exceeds current ttl",
			ttl:  time.Minute,
			claim: gojwt.MapClaims{
				"iat": now.Add(-2 * time.Minute).Unix(),
				"exp": now.Add(time.Hour).Unix(),
			},
		},
		{
			name: "missing iat claim",
			ttl:  time.Hour,
			claim: gojwt.MapClaims{
				"exp": now.Add(time.Hour).Unix(),
			},
		},
		{
			name: "invalid exp claim",
			ttl:  time.Hour,
			claim: gojwt.MapClaims{
				"iat": now.Add(-30 * time.Second).Unix(),
				"exp": "invalid",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, tc.claim)
			tokenString, err := token.SignedString([]byte("secret"))
			require.NoError(t, err)

			cache := newJWTCache()
			cache.store(tokenString, time.Hour)

			cachedToken, found := cache.get(tc.ttl)
			require.Equal(t, tc.valid, found)
			if tc.valid {
				require.Equal(t, tokenString, cachedToken)
			}
		})
	}
}

func TestJWTCacheGetUsesCurrentTTL(t *testing.T) {
	now := time.Now()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"iat": now.Add(-2 * time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("secret"))
	require.NoError(t, err)

	cache := newJWTCache()
	cache.store(tokenString, time.Hour)

	cachedToken, found := cache.get(time.Minute)
	require.False(t, found)
	require.Empty(t, cachedToken)
}
