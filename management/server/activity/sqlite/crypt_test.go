package sqlite

import (
	"bytes"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	testData := "exampl@netbird.io"
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}
	ee, err := NewFieldEncrypt(key)
	if err != nil {
		t.Fatalf("failed to init email encryption: %s", err)
	}

	encrypted, err := ee.Encrypt(testData)
	if err != nil {
		t.Fatalf("failed to encrypt data: %s", err)
	}

	if encrypted == "" {
		t.Fatalf("invalid encrypted text")
	}

	decrypted, err := ee.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt data: %s", err)
	}

	if decrypted != testData {
		t.Fatalf("decrypted data is not match with test data: %s, %s", testData, decrypted)
	}
}

func TestGenerateKeyLegacy(t *testing.T) {
	testData := "exampl@netbird.io"
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}
	ee, err := NewFieldEncrypt(key)
	if err != nil {
		t.Fatalf("failed to init email encryption: %s", err)
	}

	encrypted := ee.LegacyEncrypt(testData)
	if encrypted == "" {
		t.Fatalf("invalid encrypted text")
	}

	decrypted, err := ee.LegacyDecrypt(encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt data: %s", err)
	}

	if decrypted != testData {
		t.Fatalf("decrypted data is not match with test data: %s, %s", testData, decrypted)
	}
}

func TestCorruptKey(t *testing.T) {
	testData := "exampl@netbird.io"
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}
	ee, err := NewFieldEncrypt(key)
	if err != nil {
		t.Fatalf("failed to init email encryption: %s", err)
	}

	encrypted, err := ee.Encrypt(testData)
	if err != nil {
		t.Fatalf("failed to encrypt data: %s", err)
	}

	if encrypted == "" {
		t.Fatalf("invalid encrypted text")
	}

	newKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	ee, err = NewFieldEncrypt(newKey)
	if err != nil {
		t.Fatalf("failed to init email encryption: %s", err)
	}

	res, _ := ee.Decrypt(encrypted)
	if res == testData {
		t.Fatalf("incorrect decryption, the result is: %s", res)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Generate a key for encryption/decryption
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Initialize the FieldEncrypt with the generated key
	ec, err := NewFieldEncrypt(key)
	if err != nil {
		t.Fatalf("Failed to create FieldEncrypt: %v", err)
	}

	// Test cases
	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "Empty String",
			input: "",
		},
		{
			name:  "Short String",
			input: "Hello",
		},
		{
			name:  "String with Spaces",
			input: "Hello, World!",
		},
		{
			name:  "Long String",
			input: "The quick brown fox jumps over the lazy dog.",
		},
		{
			name:  "Unicode Characters",
			input: "こんにちは世界",
		},
		{
			name:  "Special Characters",
			input: "!@#$%^&*()_+-=[]{}|;':\",./<>?",
		},
		{
			name:  "Numeric String",
			input: "1234567890",
		},
		{
			name:  "Repeated Characters",
			input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name:  "Multi-block String",
			input: "This is a longer string that will span multiple blocks in the encryption algorithm.",
		},
		{
			name:  "Non-ASCII and ASCII Mix",
			input: "Hello 世界 123",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name+" - Legacy", func(t *testing.T) {
			// Legacy Encryption
			encryptedLegacy := ec.LegacyEncrypt(tc.input)
			if encryptedLegacy == "" {
				t.Errorf("LegacyEncrypt returned empty string for input '%s'", tc.input)
			}

			// Legacy Decryption
			decryptedLegacy, err := ec.LegacyDecrypt(encryptedLegacy)
			if err != nil {
				t.Errorf("LegacyDecrypt failed for input '%s': %v", tc.input, err)
			}

			// Verify that the decrypted value matches the original input
			if decryptedLegacy != tc.input {
				t.Errorf("LegacyDecrypt output '%s' does not match original input '%s'", decryptedLegacy, tc.input)
			}
		})

		t.Run(tc.name+" - New", func(t *testing.T) {
			// New Encryption
			encryptedNew, err := ec.Encrypt(tc.input)
			if err != nil {
				t.Errorf("Encrypt failed for input '%s': %v", tc.input, err)
			}
			if encryptedNew == "" {
				t.Errorf("Encrypt returned empty string for input '%s'", tc.input)
			}

			// New Decryption
			decryptedNew, err := ec.Decrypt(encryptedNew)
			if err != nil {
				t.Errorf("Decrypt failed for input '%s': %v", tc.input, err)
			}

			// Verify that the decrypted value matches the original input
			if decryptedNew != tc.input {
				t.Errorf("Decrypt output '%s' does not match original input '%s'", decryptedNew, tc.input)
			}
		})
	}
}

func TestPKCS5UnPadding(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    []byte
		expectError bool
	}{
		{
			name:     "Valid Padding",
			input:    append([]byte("Hello, World!"), bytes.Repeat([]byte{4}, 4)...),
			expected: []byte("Hello, World!"),
		},
		{
			name:        "Empty Input",
			input:       []byte{},
			expectError: true,
		},
		{
			name:        "Padding Length Zero",
			input:       append([]byte("Hello, World!"), bytes.Repeat([]byte{0}, 4)...),
			expectError: true,
		},
		{
			name:        "Padding Length Exceeds Block Size",
			input:       append([]byte("Hello, World!"), bytes.Repeat([]byte{17}, 17)...),
			expectError: true,
		},
		{
			name:        "Padding Length Exceeds Input Length",
			input:       []byte{5, 5, 5},
			expectError: true,
		},
		{
			name:        "Invalid Padding Bytes",
			input:       append([]byte("Hello, World!"), []byte{2, 3, 4, 5}...),
			expectError: true,
		},
		{
			name:     "Valid Single Byte Padding",
			input:    append([]byte("Hello, World!"), byte(1)),
			expected: []byte("Hello, World!"),
		},
		{
			name:        "Invalid Mixed Padding Bytes",
			input:       append([]byte("Hello, World!"), []byte{3, 3, 2}...),
			expectError: true,
		},
		{
			name:     "Valid Full Block Padding",
			input:    append([]byte("Hello, World!"), bytes.Repeat([]byte{16}, 16)...),
			expected: []byte("Hello, World!"),
		},
		{
			name:        "Non-Padding Byte at End",
			input:       append([]byte("Hello, World!"), []byte{4, 4, 4, 5}...),
			expectError: true,
		},
		{
			name:     "Valid Padding with Different Text Length",
			input:    append([]byte("Test"), bytes.Repeat([]byte{12}, 12)...),
			expected: []byte("Test"),
		},
		{
			name:     "Padding Length Equal to Input Length",
			input:    bytes.Repeat([]byte{8}, 8),
			expected: []byte{},
		},
		{
			name:        "Invalid Padding Length Zero (Again)",
			input:       append([]byte("Test"), byte(0)),
			expectError: true,
		},
		{
			name:        "Padding Length Greater Than Input",
			input:       []byte{10},
			expectError: true,
		},
		{
			name:     "Input Length Not Multiple of Block Size",
			input:    append([]byte("Invalid Length"), byte(1)),
			expected: []byte("Invalid Length"),
		},
		{
			name:     "Valid Padding with Non-ASCII Characters",
			input:    append([]byte("こんにちは"), bytes.Repeat([]byte{2}, 2)...),
			expected: []byte("こんにちは"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := pkcs5UnPadding(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error but got: %v", err)
				}
				if !bytes.Equal(result, tt.expected) {
					t.Errorf("Expected output %v, got %v", tt.expected, result)
				}
			}
		})
	}
}
