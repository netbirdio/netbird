package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

// legacyIV is the static IV used by the legacy CBC encryption.
// Deprecated: This is kept only for backward compatibility with existing encrypted data.
var legacyIV = []byte{10, 22, 13, 79, 05, 8, 52, 91, 87, 98, 88, 98, 35, 25, 13, 05}

// LegacyEncrypt encrypts plaintext using AES-CBC with a static IV.
// Deprecated: Use Encrypt instead. This method is kept only for backward compatibility.
func (f *FieldEncrypt) LegacyEncrypt(plaintext string) string {
	padded := pkcs5Padding([]byte(plaintext))
	ciphertext := make([]byte, len(padded))
	cbc := cipher.NewCBCEncrypter(f.block, legacyIV)
	cbc.CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// LegacyDecrypt decrypts ciphertext that was encrypted using AES-CBC with a static IV.
// Deprecated: This method is kept only for backward compatibility with existing encrypted data.
func (f *FieldEncrypt) LegacyDecrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	cbc := cipher.NewCBCDecrypter(f.block, legacyIV)
	cbc.CryptBlocks(data, data)

	plaintext, err := pkcs5UnPadding(data)
	if err != nil {
		return "", fmt.Errorf("unpad plaintext: %w", err)
	}

	return string(plaintext), nil
}

// pkcs5Padding adds PKCS#5 padding to the input.
func pkcs5Padding(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs5UnPadding removes PKCS#5 padding from the input.
func pkcs5UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("input data is empty")
	}

	paddingLen := int(data[length-1])
	if paddingLen == 0 || paddingLen > aes.BlockSize || paddingLen > length {
		return nil, fmt.Errorf("invalid padding size")
	}

	// Verify that all padding bytes are the same
	for i := 0; i < paddingLen; i++ {
		if data[length-1-i] != byte(paddingLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:length-paddingLen], nil
}
