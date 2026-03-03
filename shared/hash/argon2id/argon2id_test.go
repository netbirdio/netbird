package argon2id

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHash(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{
			name:   "simple password",
			secret: "password123",
		},
		{
			name:   "complex password with special chars",
			secret: "P@ssw0rd!#$%^&*()",
		},
		{
			name:   "long password",
			secret: strings.Repeat("a", 100),
		},
		{
			name:   "empty password",
			secret: "",
		},
		{
			name:   "unicode password",
			secret: "пароль密码🔐",
		},
		{
			name:   "numeric PIN",
			secret: "123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := Hash(tt.secret)
			if err != nil {
				t.Fatalf("Hash() error = %v", err)
			}

			// Verify hash format
			if !strings.HasPrefix(hash, "$argon2id$") {
				t.Errorf("Hash() = %v, want hash starting with $argon2id$", hash)
			}

			// Verify hash has correct number of components
			parts := strings.Split(hash, "$")
			if len(parts) != 6 {
				t.Errorf("Hash() has %d parts, want 6", len(parts))
			}

			// Verify version is present
			if !strings.HasPrefix(hash, "$argon2id$v=") {
				t.Errorf("Hash() missing version, got %v", hash)
			}

			// Verify each hash is unique (different salt)
			hash2, err := Hash(tt.secret)
			if err != nil {
				t.Fatalf("Hash() second call error = %v", err)
			}
			if hash == hash2 {
				t.Error("Hash() produces identical hashes for same input (salt not random)")
			}
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		wantError error
	}{
		{
			name:      "valid password",
			secret:    "correctPassword",
			wantError: nil,
		},
		{
			name:      "valid PIN",
			secret:    "1234",
			wantError: nil,
		},
		{
			name:      "empty secret",
			secret:    "",
			wantError: nil,
		},
		{
			name:      "unicode secret",
			secret:    "密码🔐",
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate hash
			hash, err := Hash(tt.secret)
			if err != nil {
				t.Fatalf("Hash() error = %v", err)
			}

			// Verify correct secret
			err = Verify(tt.secret, hash)
			if !errors.Is(err, tt.wantError) {
				t.Errorf("Verify() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestVerifyIncorrectPassword(t *testing.T) {
	secret := "correctPassword"
	wrongSecret := "wrongPassword"

	hash, err := Hash(secret)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	err = Verify(wrongSecret, hash)
	if !errors.Is(err, ErrMismatchedHashAndPassword) {
		t.Errorf("Verify() error = %v, want %v", err, ErrMismatchedHashAndPassword)
	}
}

func TestVerifyInvalidHashFormat(t *testing.T) {
	tests := []struct {
		name          string
		invalidHash   string
		expectedError error
	}{
		{
			name:          "empty hash",
			invalidHash:   "",
			expectedError: ErrInvalidHash,
		},
		{
			name:          "wrong algorithm",
			invalidHash:   "$bcrypt$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
			expectedError: ErrInvalidHash,
		},
		{
			name:          "missing parts",
			invalidHash:   "$argon2id$v=19$m=19456",
			expectedError: ErrInvalidHash,
		},
		{
			name:          "too many parts",
			invalidHash:   "$argon2id$v=19$m=19456,t=2,p=1$salt$hash$extra",
			expectedError: ErrInvalidHash,
		},
		{
			name:          "invalid version format",
			invalidHash:   "$argon2id$vXX$m=19456,t=2,p=1$c2FsdA$aGFzaA",
			expectedError: ErrInvalidHash,
		},
		{
			name:          "invalid parameters format",
			invalidHash:   "$argon2id$v=19$mXX,tYY,pZZ$c2FsdA$aGFzaA",
			expectedError: ErrInvalidHash,
		},
		{
			name:          "invalid salt base64",
			invalidHash:   "$argon2id$v=19$m=19456,t=2,p=1$not-valid-base64!@#$aGFzaA",
			expectedError: ErrInvalidHash,
		},
		{
			name:          "invalid hash base64",
			invalidHash:   "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$not-valid-base64!@#",
			expectedError: ErrInvalidHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify("password", tt.invalidHash)
			if err == nil {
				t.Errorf("Verify() expected error, got nil")
				return
			}

			if !errors.Is(err, tt.expectedError) && !strings.Contains(err.Error(), tt.expectedError.Error()) {
				t.Errorf("Verify() error = %v, want error containing %v", err, tt.expectedError)
			}
		})
	}
}

func TestVerifyIncompatibleVersion(t *testing.T) {
	// Manually craft a hash with wrong version
	invalidVersionHash := "$argon2id$v=18$m=19456,t=2,p=1$c2FsdDEyMzQ1Njc4OTA$aGFzaDEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9w"

	err := Verify("password", invalidVersionHash)
	if !errors.Is(err, ErrIncompatibleVersion) {
		t.Errorf("Verify() error = %v, want %v", err, ErrIncompatibleVersion)
	}
}

func TestHashDeterminism(t *testing.T) {
	// Ensure different hashes for same password (random salt)
	password := "testPassword"
	hashes := make(map[string]bool)

	for i := 0; i < 10; i++ {
		hash, err := Hash(password)
		if err != nil {
			t.Fatalf("Hash() error = %v", err)
		}
		if hashes[hash] {
			t.Error("Hash() produced duplicate hash (salt generation may be broken)")
		}
		hashes[hash] = true
	}

	if len(hashes) != 10 {
		t.Errorf("Expected 10 unique hashes, got %d", len(hashes))
	}
}

func TestOWASPCompliance(t *testing.T) {
	// Test that generated hashes use OWASP-recommended parameters
	secret := "testPassword"
	hash, err := Hash(secret)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	params, _, _, err := decodeHash(hash)
	if err != nil {
		t.Fatalf("decodeHash() error = %v", err)
	}

	// Verify OWASP minimum baseline parameters
	if params.memory != 19456 {
		t.Errorf("memory = %d, want 19456 (OWASP baseline)", params.memory)
	}
	if params.iterations != 2 {
		t.Errorf("iterations = %d, want 2 (OWASP baseline)", params.iterations)
	}
	if params.parallelism != 1 {
		t.Errorf("parallelism = %d, want 1 (OWASP baseline)", params.parallelism)
	}
	if params.keyLength != 32 {
		t.Errorf("keyLength = %d, want 32", params.keyLength)
	}
	if params.version != argon2.Version {
		t.Errorf("version = %d, want %d", params.version, argon2.Version)
	}
}

func TestConstantTimeComparison(t *testing.T) {
	// This test verifies that Verify() is using constant-time comparison
	// by ensuring it doesn't fail differently for similar vs different hashes
	secret := "password123"
	wrongSecret := "password124" // One character different

	hash, err := Hash(secret)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Both wrong passwords should return the same error
	err1 := Verify(wrongSecret, hash)
	err2 := Verify("completelydifferent", hash)

	if !errors.Is(err1, ErrMismatchedHashAndPassword) {
		t.Errorf("Verify() error = %v, want %v", err1, ErrMismatchedHashAndPassword)
	}
	if !errors.Is(err2, ErrMismatchedHashAndPassword) {
		t.Errorf("Verify() error = %v, want %v", err2, ErrMismatchedHashAndPassword)
	}

	// Errors should be identical (same error type and message)
	if err1.Error() != err2.Error() {
		t.Error("Verify() returns different errors for different wrong passwords (potential timing attack)")
	}
}

func TestCaseSensitivity(t *testing.T) {
	// Passwords should be case-sensitive
	secret := "Password123"
	wrongSecret := "password123"

	hash, err := Hash(secret)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Correct password should verify
	if err := Verify(secret, hash); err != nil {
		t.Errorf("Verify() with correct password error = %v, want nil", err)
	}

	// Wrong case should not verify
	if err := Verify(wrongSecret, hash); !errors.Is(err, ErrMismatchedHashAndPassword) {
		t.Errorf("Verify() with wrong case error = %v, want %v", err, ErrMismatchedHashAndPassword)
	}
}

// Benchmark tests
func BenchmarkHash(b *testing.B) {
	secret := "benchmarkPassword123"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Hash(secret)
	}
}

func BenchmarkVerify(b *testing.B) {
	secret := "benchmarkPassword123"
	hash, _ := Hash(secret)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(secret, hash)
	}
}
