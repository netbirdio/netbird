package types

import (
	"crypto/sha256"
	b64 "encoding/base64"
	"hash/crc32"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/base62"
	"github.com/netbirdio/netbird/util/crypt"
)

func TestUserInviteRecord_TableName(t *testing.T) {
	invite := UserInviteRecord{}
	assert.Equal(t, "user_invites", invite.TableName())
}

func TestGenerateInviteToken_Success(t *testing.T) {
	hashedToken, plainToken, err := GenerateInviteToken()
	require.NoError(t, err)
	assert.NotEmpty(t, hashedToken)
	assert.NotEmpty(t, plainToken)
}

func TestGenerateInviteToken_Length(t *testing.T) {
	_, plainToken, err := GenerateInviteToken()
	require.NoError(t, err)
	assert.Len(t, plainToken, InviteTokenLength)
}

func TestGenerateInviteToken_Prefix(t *testing.T) {
	_, plainToken, err := GenerateInviteToken()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(plainToken, InviteTokenPrefix))
}

func TestGenerateInviteToken_Hashing(t *testing.T) {
	hashedToken, plainToken, err := GenerateInviteToken()
	require.NoError(t, err)

	expectedHash := sha256.Sum256([]byte(plainToken))
	expectedHashedToken := b64.StdEncoding.EncodeToString(expectedHash[:])
	assert.Equal(t, expectedHashedToken, hashedToken)
}

func TestGenerateInviteToken_Checksum(t *testing.T) {
	_, plainToken, err := GenerateInviteToken()
	require.NoError(t, err)

	// Extract parts
	secret := plainToken[len(InviteTokenPrefix) : len(InviteTokenPrefix)+InviteTokenSecretLength]
	checksumStr := plainToken[len(InviteTokenPrefix)+InviteTokenSecretLength:]

	// Verify checksum
	expectedChecksum := crc32.ChecksumIEEE([]byte(secret))
	actualChecksum, err := base62.Decode(checksumStr)
	require.NoError(t, err)
	assert.Equal(t, expectedChecksum, actualChecksum)
}

func TestGenerateInviteToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		_, plainToken, err := GenerateInviteToken()
		require.NoError(t, err)
		assert.False(t, tokens[plainToken], "Token should be unique")
		tokens[plainToken] = true
	}
}

func TestHashInviteToken(t *testing.T) {
	token := "nbi_testtoken123456789012345678901234"
	hashedToken := HashInviteToken(token)

	expectedHash := sha256.Sum256([]byte(token))
	expectedHashedToken := b64.StdEncoding.EncodeToString(expectedHash[:])
	assert.Equal(t, expectedHashedToken, hashedToken)
}

func TestHashInviteToken_Consistency(t *testing.T) {
	token := "nbi_testtoken123456789012345678901234"
	hash1 := HashInviteToken(token)
	hash2 := HashInviteToken(token)
	assert.Equal(t, hash1, hash2)
}

func TestHashInviteToken_DifferentTokens(t *testing.T) {
	token1 := "nbi_testtoken123456789012345678901234"
	token2 := "nbi_testtoken123456789012345678901235"
	hash1 := HashInviteToken(token1)
	hash2 := HashInviteToken(token2)
	assert.NotEqual(t, hash1, hash2)
}

func TestValidateInviteToken_Success(t *testing.T) {
	_, plainToken, err := GenerateInviteToken()
	require.NoError(t, err)

	err = ValidateInviteToken(plainToken)
	assert.NoError(t, err)
}

func TestValidateInviteToken_InvalidLength(t *testing.T) {
	testCases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"too short", "nbi_abc"},
		{"too long", "nbi_" + strings.Repeat("a", 50)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateInviteToken(tc.token)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid token length")
		})
	}
}

func TestValidateInviteToken_InvalidPrefix(t *testing.T) {
	// Create a token with wrong prefix but correct length
	token := "xyz_" + strings.Repeat("a", 30) + "000000"
	err := ValidateInviteToken(token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token prefix")
}

func TestValidateInviteToken_InvalidChecksum(t *testing.T) {
	// Create a token with correct format but invalid checksum
	token := InviteTokenPrefix + strings.Repeat("a", InviteTokenSecretLength) + "ZZZZZZ"
	err := ValidateInviteToken(token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum")
}

func TestValidateInviteToken_ModifiedToken(t *testing.T) {
	_, plainToken, err := GenerateInviteToken()
	require.NoError(t, err)

	// Modify one character in the secret part
	modifiedToken := plainToken[:5] + "X" + plainToken[6:]
	err = ValidateInviteToken(modifiedToken)
	require.Error(t, err)
}

func TestUserInviteRecord_IsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		invite := &UserInviteRecord{
			ExpiresAt: time.Now().Add(time.Hour),
		}
		assert.False(t, invite.IsExpired())
	})

	t.Run("expired", func(t *testing.T) {
		invite := &UserInviteRecord{
			ExpiresAt: time.Now().Add(-time.Hour),
		}
		assert.True(t, invite.IsExpired())
	})

	t.Run("just expired", func(t *testing.T) {
		invite := &UserInviteRecord{
			ExpiresAt: time.Now().Add(-time.Second),
		}
		assert.True(t, invite.IsExpired())
	})
}

func TestNewInviteID(t *testing.T) {
	id := NewInviteID()
	assert.NotEmpty(t, id)
	assert.Len(t, id, 20) // xid generates 20 character IDs
}

func TestNewInviteID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := NewInviteID()
		assert.False(t, ids[id], "ID should be unique")
		ids[id] = true
	}
}

func TestUserInviteRecord_EncryptDecryptSensitiveData(t *testing.T) {
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)

	t.Run("encrypt and decrypt", func(t *testing.T) {
		invite := &UserInviteRecord{
			ID:        "test-invite",
			AccountID: "test-account",
			Email:     "test@example.com",
			Name:      "Test User",
			Role:      "user",
		}

		// Encrypt
		err := invite.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		// Verify encrypted values are different from original
		assert.NotEqual(t, "test@example.com", invite.Email)
		assert.NotEqual(t, "Test User", invite.Name)

		// Decrypt
		err = invite.DecryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		// Verify decrypted values match original
		assert.Equal(t, "test@example.com", invite.Email)
		assert.Equal(t, "Test User", invite.Name)
	})

	t.Run("encrypt empty fields", func(t *testing.T) {
		invite := &UserInviteRecord{
			ID:        "test-invite",
			AccountID: "test-account",
			Email:     "",
			Name:      "",
			Role:      "user",
		}

		err := invite.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)
		assert.Equal(t, "", invite.Email)
		assert.Equal(t, "", invite.Name)

		err = invite.DecryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)
		assert.Equal(t, "", invite.Email)
		assert.Equal(t, "", invite.Name)
	})

	t.Run("nil encryptor", func(t *testing.T) {
		invite := &UserInviteRecord{
			ID:        "test-invite",
			AccountID: "test-account",
			Email:     "test@example.com",
			Name:      "Test User",
			Role:      "user",
		}

		err := invite.EncryptSensitiveData(nil)
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", invite.Email)
		assert.Equal(t, "Test User", invite.Name)

		err = invite.DecryptSensitiveData(nil)
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", invite.Email)
		assert.Equal(t, "Test User", invite.Name)
	})
}

func TestUserInviteRecord_Copy(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(72 * time.Hour)

	original := &UserInviteRecord{
		ID:          "invite-id",
		AccountID:   "account-id",
		Email:       "test@example.com",
		Name:        "Test User",
		Role:        "user",
		AutoGroups:  []string{"group1", "group2"},
		HashedToken: "hashed-token",
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
		CreatedBy:   "creator-id",
	}

	copied := original.Copy()

	// Verify all fields are copied
	assert.Equal(t, original.ID, copied.ID)
	assert.Equal(t, original.AccountID, copied.AccountID)
	assert.Equal(t, original.Email, copied.Email)
	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Role, copied.Role)
	assert.Equal(t, original.AutoGroups, copied.AutoGroups)
	assert.Equal(t, original.HashedToken, copied.HashedToken)
	assert.Equal(t, original.ExpiresAt, copied.ExpiresAt)
	assert.Equal(t, original.CreatedAt, copied.CreatedAt)
	assert.Equal(t, original.CreatedBy, copied.CreatedBy)

	// Verify deep copy of AutoGroups (modifying copy doesn't affect original)
	copied.AutoGroups[0] = "modified"
	assert.NotEqual(t, original.AutoGroups[0], copied.AutoGroups[0])
	assert.Equal(t, "group1", original.AutoGroups[0])
}

func TestUserInviteRecord_Copy_EmptyAutoGroups(t *testing.T) {
	original := &UserInviteRecord{
		ID:         "invite-id",
		AccountID:  "account-id",
		AutoGroups: []string{},
	}

	copied := original.Copy()
	assert.NotNil(t, copied.AutoGroups)
	assert.Len(t, copied.AutoGroups, 0)
}

func TestUserInviteRecord_Copy_NilAutoGroups(t *testing.T) {
	original := &UserInviteRecord{
		ID:         "invite-id",
		AccountID:  "account-id",
		AutoGroups: nil,
	}

	copied := original.Copy()
	assert.NotNil(t, copied.AutoGroups)
	assert.Len(t, copied.AutoGroups, 0)
}

func TestInviteTokenConstants(t *testing.T) {
	// Verify constants are consistent
	expectedLength := len(InviteTokenPrefix) + InviteTokenSecretLength + InviteTokenChecksumLength
	assert.Equal(t, InviteTokenLength, expectedLength)
	assert.Equal(t, 4, len(InviteTokenPrefix))
	assert.Equal(t, 30, InviteTokenSecretLength)
	assert.Equal(t, 6, InviteTokenChecksumLength)
	assert.Equal(t, 40, InviteTokenLength)
	assert.Equal(t, 259200, DefaultInviteExpirationSeconds) // 72 hours
	assert.Equal(t, 3600, MinInviteExpirationSeconds)       // 1 hour
}

func TestGenerateInviteToken_ValidatesOwnOutput(t *testing.T) {
	// Generate multiple tokens and ensure they all validate
	for i := 0; i < 50; i++ {
		_, plainToken, err := GenerateInviteToken()
		require.NoError(t, err)

		err = ValidateInviteToken(plainToken)
		assert.NoError(t, err, "Generated token should always be valid")
	}
}

func TestHashInviteToken_MatchesGeneratedHash(t *testing.T) {
	hashedToken, plainToken, err := GenerateInviteToken()
	require.NoError(t, err)

	// HashInviteToken should produce the same hash as GenerateInviteToken
	rehashedToken := HashInviteToken(plainToken)
	assert.Equal(t, hashedToken, rehashedToken)
}
