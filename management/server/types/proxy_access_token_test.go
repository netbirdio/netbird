package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlainProxyToken_Validate(t *testing.T) {
	tests := []struct {
		name    string
		token   PlainProxyToken
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid token",
			token:   "", // will be generated
			wantErr: false,
		},
		{
			name:    "wrong prefix",
			token:   "xyz_8FbPkxioCFmlvCTJbD1RafygfVmS9z15lyNM",
			wantErr: true,
			errMsg:  "invalid token prefix",
		},
		{
			name:    "too short",
			token:   "nbx_short",
			wantErr: true,
			errMsg:  "invalid token length",
		},
		{
			name:    "too long",
			token:   "nbx_8FbPkxioCFmlvCTJbD1RafygfVmS9z15lyNMextra",
			wantErr: true,
			errMsg:  "invalid token length",
		},
		{
			name:    "correct length but invalid checksum",
			token:   "nbx_invalidtoken123456789012345678901234", // exactly 40 chars, invalid checksum
			wantErr: true,
			errMsg:  "invalid token checksum",
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
			errMsg:  "invalid token prefix",
		},
		{
			name:    "only prefix",
			token:   "nbx_",
			wantErr: true,
			errMsg:  "invalid token length",
		},
	}

	// Generate a valid token for the first test
	generated, err := CreateNewProxyAccessToken("test", 0, nil, "test")
	require.NoError(t, err)
	tests[0].token = generated.PlainToken

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.token.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPlainProxyToken_Hash(t *testing.T) {
	token1 := PlainProxyToken("nbx_8FbPkxioCFmlvCTJbD1RafygfVmS9z15lyNM")
	token2 := PlainProxyToken("nbx_8FbPkxioCFmlvCTJbD1RafygfVmS9z15lyNM")
	token3 := PlainProxyToken("nbx_differenttoken1234567890123456789X")

	hash1 := token1.Hash()
	hash2 := token2.Hash()
	hash3 := token3.Hash()

	assert.Equal(t, hash1, hash2, "same token should produce same hash")
	assert.NotEqual(t, hash1, hash3, "different tokens should produce different hashes")
	assert.NotEmpty(t, hash1)
}

func TestCreateNewProxyAccessToken(t *testing.T) {
	t.Run("creates valid token", func(t *testing.T) {
		generated, err := CreateNewProxyAccessToken("test-token", 0, nil, "test-user")
		require.NoError(t, err)

		assert.NotEmpty(t, generated.ID)
		assert.Equal(t, "test-token", generated.Name)
		assert.Equal(t, "test-user", generated.CreatedBy)
		assert.NotEmpty(t, generated.HashedToken)
		assert.NotEmpty(t, generated.PlainToken)
		assert.Nil(t, generated.ExpiresAt)
		assert.False(t, generated.Revoked)

		assert.NoError(t, generated.PlainToken.Validate())
		assert.Equal(t, ProxyTokenLength, len(generated.PlainToken))
		assert.Equal(t, ProxyTokenPrefix, string(generated.PlainToken[:len(ProxyTokenPrefix)]))
	})

	t.Run("tokens are unique", func(t *testing.T) {
		gen1, err := CreateNewProxyAccessToken("test1", 0, nil, "user")
		require.NoError(t, err)

		gen2, err := CreateNewProxyAccessToken("test2", 0, nil, "user")
		require.NoError(t, err)

		assert.NotEqual(t, gen1.PlainToken, gen2.PlainToken)
		assert.NotEqual(t, gen1.HashedToken, gen2.HashedToken)
		assert.NotEqual(t, gen1.ID, gen2.ID)
	})
}

func TestProxyAccessToken_IsExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	t.Run("expired token", func(t *testing.T) {
		token := &ProxyAccessToken{ExpiresAt: &past}
		assert.True(t, token.IsExpired())
	})

	t.Run("not expired token", func(t *testing.T) {
		token := &ProxyAccessToken{ExpiresAt: &future}
		assert.False(t, token.IsExpired())
	})

	t.Run("no expiration", func(t *testing.T) {
		token := &ProxyAccessToken{ExpiresAt: nil}
		assert.False(t, token.IsExpired())
	})
}

func TestProxyAccessToken_IsValid(t *testing.T) {
	token := &ProxyAccessToken{
		Revoked: false,
	}

	assert.True(t, token.IsValid())

	token.Revoked = true
	assert.False(t, token.IsValid())
}
