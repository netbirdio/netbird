package sshauth

import (
	"testing"
)

func TestHashUserID(t *testing.T) {
	tests := []struct {
		name   string
		userID string
	}{
		{
			name:   "simple user ID",
			userID: "user@example.com",
		},
		{
			name:   "UUID format",
			userID: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:   "numeric ID",
			userID: "12345",
		},
		{
			name:   "empty string",
			userID: "",
		},
		{
			name:   "special characters",
			userID: "user+test@domain.com",
		},
		{
			name:   "unicode characters",
			userID: "用户@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashUserID(tt.userID)
			if err != nil {
				t.Errorf("HashUserID() error = %v, want nil", err)
				return
			}

			// Verify hash is non-zero for non-empty inputs
			if tt.userID != "" && hash == 0 {
				t.Errorf("HashUserID() returned zero hash for non-empty input")
			}
		})
	}
}

func TestHashUserID_Consistency(t *testing.T) {
	userID := "test@example.com"

	hash1, err1 := HashUserID(userID)
	if err1 != nil {
		t.Fatalf("First HashUserID() error = %v", err1)
	}

	hash2, err2 := HashUserID(userID)
	if err2 != nil {
		t.Fatalf("Second HashUserID() error = %v", err2)
	}

	if hash1 != hash2 {
		t.Errorf("HashUserID() is not consistent: got %v and %v for same input", hash1, hash2)
	}
}

func TestHashUserID_Uniqueness(t *testing.T) {
	tests := []struct {
		userID1 string
		userID2 string
	}{
		{"user1@example.com", "user2@example.com"},
		{"alice@domain.com", "bob@domain.com"},
		{"test", "test1"},
		{"", "a"},
	}

	for _, tt := range tests {
		hash1, err1 := HashUserID(tt.userID1)
		if err1 != nil {
			t.Fatalf("HashUserID(%s) error = %v", tt.userID1, err1)
		}

		hash2, err2 := HashUserID(tt.userID2)
		if err2 != nil {
			t.Fatalf("HashUserID(%s) error = %v", tt.userID2, err2)
		}

		if hash1 == hash2 {
			t.Errorf("HashUserID() collision: %s and %s produced same hash %v", tt.userID1, tt.userID2, hash1)
		}
	}
}

func TestUserIDHash_String(t *testing.T) {
	tests := []struct {
		name     string
		hash     UserIDHash
		expected string
	}{
		{
			name:     "zero hash",
			hash:     UserIDHash(0),
			expected: "0000000000000000",
		},
		{
			name:     "small value",
			hash:     UserIDHash(255),
			expected: "00000000000000ff",
		},
		{
			name:     "large value",
			hash:     UserIDHash(0xdeadbeefcafebabe),
			expected: "deadbeefcafebabe",
		},
		{
			name:     "max value",
			hash:     UserIDHash(0xffffffffffffffff),
			expected: "ffffffffffffffff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.hash.String()
			if result != tt.expected {
				t.Errorf("UserIDHash.String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestUserIDHash_String_Length(t *testing.T) {
	// Test that String() always returns 16 hex characters
	userID := "test@example.com"
	hash, err := HashUserID(userID)
	if err != nil {
		t.Fatalf("HashUserID() error = %v", err)
	}

	result := hash.String()
	if len(result) != 16 {
		t.Errorf("UserIDHash.String() length = %d, want 16", len(result))
	}

	// Verify it's valid hex
	for i, c := range result {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("UserIDHash.String() contains non-hex character at position %d: %c", i, c)
		}
	}
}

func TestHashUserID_KnownValues(t *testing.T) {
	// Test with known FNV-1a values to ensure correct implementation
	tests := []struct {
		name     string
		userID   string
		expected UserIDHash
	}{
		{
			name:     "empty string",
			userID:   "",
			expected: UserIDHash(0xcbf29ce484222325), // FNV-1a offset basis
		},
		{
			name:     "single character 'a'",
			userID:   "a",
			expected: UserIDHash(0xaf63dc4c8601ec8c),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashUserID(tt.userID)
			if err != nil {
				t.Errorf("HashUserID() error = %v", err)
				return
			}

			if hash != tt.expected {
				t.Errorf("HashUserID(%q) = %v (0x%x), want %v (0x%x)",
					tt.userID, hash, uint64(hash), tt.expected, uint64(tt.expected))
			}
		})
	}
}

func BenchmarkHashUserID(b *testing.B) {
	userID := "user@example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = HashUserID(userID)
	}
}

func BenchmarkUserIDHash_String(b *testing.B) {
	hash := UserIDHash(0xdeadbeefcafebabe)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hash.String()
	}
}
