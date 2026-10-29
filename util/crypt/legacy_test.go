package crypt

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegacyEncryptDecrypt(t *testing.T) {
	testData := "exampl@netbird.io"
	key, err := GenerateKey()
	require.NoError(t, err)

	ec, err := NewFieldEncrypt(key)
	require.NoError(t, err)

	encrypted := ec.LegacyEncrypt(testData)
	assert.NotEmpty(t, encrypted)

	decrypted, err := ec.LegacyDecrypt(encrypted)
	require.NoError(t, err)

	assert.Equal(t, testData, decrypted)
}

func TestLegacyEncryptDecryptVariousInputs(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	ec, err := NewFieldEncrypt(key)
	require.NoError(t, err)

	testCases := []struct {
		name  string
		input string
	}{
		{name: "Empty String", input: ""},
		{name: "Short String", input: "Hello"},
		{name: "String with Spaces", input: "Hello, World!"},
		{name: "Long String", input: "The quick brown fox jumps over the lazy dog."},
		{name: "Unicode Characters", input: "こんにちは世界"},
		{name: "Special Characters", input: "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{name: "Numeric String", input: "1234567890"},
		{name: "Repeated Characters", input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{name: "Multi-block String", input: "This is a longer string that will span multiple blocks in the encryption algorithm."},
		{name: "Non-ASCII and ASCII Mix", input: "Hello 世界 123"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted := ec.LegacyEncrypt(tc.input)
			assert.NotEmpty(t, encrypted)

			decrypted, err := ec.LegacyDecrypt(encrypted)
			require.NoError(t, err)

			assert.Equal(t, tc.input, decrypted)
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
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
