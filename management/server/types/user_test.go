package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/util/crypt"
)

func TestUser_EncryptSensitiveData(t *testing.T) {
	key, err := crypt.GenerateKey()
	require.NoError(t, err)

	fieldEncrypt, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)

	t.Run("encrypt email and name", func(t *testing.T) {
		user := &User{
			Id:    "user-1",
			Email: "test@example.com",
			Name:  "Test User",
		}

		err := user.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		assert.NotEqual(t, "test@example.com", user.Email, "email should be encrypted")
		assert.NotEqual(t, "Test User", user.Name, "name should be encrypted")
		assert.NotEmpty(t, user.Email, "encrypted email should not be empty")
		assert.NotEmpty(t, user.Name, "encrypted name should not be empty")
	})

	t.Run("encrypt empty email and name", func(t *testing.T) {
		user := &User{
			Id:    "user-2",
			Email: "",
			Name:  "",
		}

		err := user.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		assert.Equal(t, "", user.Email, "empty email should remain empty")
		assert.Equal(t, "", user.Name, "empty name should remain empty")
	})

	t.Run("encrypt only email", func(t *testing.T) {
		user := &User{
			Id:    "user-3",
			Email: "test@example.com",
			Name:  "",
		}

		err := user.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		assert.NotEqual(t, "test@example.com", user.Email, "email should be encrypted")
		assert.NotEmpty(t, user.Email, "encrypted email should not be empty")
		assert.Equal(t, "", user.Name, "empty name should remain empty")
	})

	t.Run("encrypt only name", func(t *testing.T) {
		user := &User{
			Id:    "user-4",
			Email: "",
			Name:  "Test User",
		}

		err := user.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		assert.Equal(t, "", user.Email, "empty email should remain empty")
		assert.NotEqual(t, "Test User", user.Name, "name should be encrypted")
		assert.NotEmpty(t, user.Name, "encrypted name should not be empty")
	})

	t.Run("nil encryptor returns no error", func(t *testing.T) {
		user := &User{
			Id:    "user-5",
			Email: "test@example.com",
			Name:  "Test User",
		}

		err := user.EncryptSensitiveData(nil)
		require.NoError(t, err)

		assert.Equal(t, "test@example.com", user.Email, "email should remain unchanged with nil encryptor")
		assert.Equal(t, "Test User", user.Name, "name should remain unchanged with nil encryptor")
	})
}

func TestUser_DecryptSensitiveData(t *testing.T) {
	key, err := crypt.GenerateKey()
	require.NoError(t, err)

	fieldEncrypt, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)

	t.Run("decrypt email and name", func(t *testing.T) {
		originalEmail := "test@example.com"
		originalName := "Test User"

		user := &User{
			Id:    "user-1",
			Email: originalEmail,
			Name:  originalName,
		}

		err := user.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		err = user.DecryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		assert.Equal(t, originalEmail, user.Email, "decrypted email should match original")
		assert.Equal(t, originalName, user.Name, "decrypted name should match original")
	})

	t.Run("decrypt empty email and name", func(t *testing.T) {
		user := &User{
			Id:    "user-2",
			Email: "",
			Name:  "",
		}

		err := user.DecryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		assert.Equal(t, "", user.Email, "empty email should remain empty")
		assert.Equal(t, "", user.Name, "empty name should remain empty")
	})

	t.Run("decrypt only email", func(t *testing.T) {
		originalEmail := "test@example.com"

		user := &User{
			Id:    "user-3",
			Email: originalEmail,
			Name:  "",
		}

		err := user.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		err = user.DecryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		assert.Equal(t, originalEmail, user.Email, "decrypted email should match original")
		assert.Equal(t, "", user.Name, "empty name should remain empty")
	})

	t.Run("decrypt only name", func(t *testing.T) {
		originalName := "Test User"

		user := &User{
			Id:    "user-4",
			Email: "",
			Name:  originalName,
		}

		err := user.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		err = user.DecryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		assert.Equal(t, "", user.Email, "empty email should remain empty")
		assert.Equal(t, originalName, user.Name, "decrypted name should match original")
	})

	t.Run("nil encryptor returns no error", func(t *testing.T) {
		user := &User{
			Id:    "user-5",
			Email: "test@example.com",
			Name:  "Test User",
		}

		err := user.DecryptSensitiveData(nil)
		require.NoError(t, err)

		assert.Equal(t, "test@example.com", user.Email, "email should remain unchanged with nil encryptor")
		assert.Equal(t, "Test User", user.Name, "name should remain unchanged with nil encryptor")
	})

	t.Run("decrypt with invalid ciphertext returns error", func(t *testing.T) {
		user := &User{
			Id:    "user-6",
			Email: "not-valid-base64-ciphertext!!!",
			Name:  "Test User",
		}

		err := user.DecryptSensitiveData(fieldEncrypt)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decrypt email")
	})

	t.Run("decrypt with wrong key returns error", func(t *testing.T) {
		originalEmail := "test@example.com"
		originalName := "Test User"

		user := &User{
			Id:    "user-7",
			Email: originalEmail,
			Name:  originalName,
		}

		err := user.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		differentKey, err := crypt.GenerateKey()
		require.NoError(t, err)

		differentEncrypt, err := crypt.NewFieldEncrypt(differentKey)
		require.NoError(t, err)

		err = user.DecryptSensitiveData(differentEncrypt)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decrypt email")
	})
}

func TestUser_EncryptDecryptRoundTrip(t *testing.T) {
	key, err := crypt.GenerateKey()
	require.NoError(t, err)

	fieldEncrypt, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)

	testCases := []struct {
		name  string
		email string
		uname string
	}{
		{
			name:  "standard email and name",
			email: "user@example.com",
			uname: "John Doe",
		},
		{
			name:  "email with special characters",
			email: "user+tag@sub.example.com",
			uname: "O'Brien, Mary-Jane",
		},
		{
			name:  "unicode characters",
			email: "user@example.com",
			uname: "Jean-Pierre Müller 日本語",
		},
		{
			name:  "long values",
			email: "very.long.email.address.that.is.quite.extended@subdomain.example.organization.com",
			uname: "A Very Long Name That Contains Many Words And Is Quite Extended For Testing Purposes",
		},
		{
			name:  "empty email only",
			email: "",
			uname: "Name Only",
		},
		{
			name:  "empty name only",
			email: "email@only.com",
			uname: "",
		},
		{
			name:  "both empty",
			email: "",
			uname: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := &User{
				Id:    "test-user",
				Email: tc.email,
				Name:  tc.uname,
			}

			err := user.EncryptSensitiveData(fieldEncrypt)
			require.NoError(t, err)

			if tc.email != "" {
				assert.NotEqual(t, tc.email, user.Email, "email should be encrypted")
			}
			if tc.uname != "" {
				assert.NotEqual(t, tc.uname, user.Name, "name should be encrypted")
			}

			err = user.DecryptSensitiveData(fieldEncrypt)
			require.NoError(t, err)

			assert.Equal(t, tc.email, user.Email, "decrypted email should match original")
			assert.Equal(t, tc.uname, user.Name, "decrypted name should match original")
		})
	}
}
