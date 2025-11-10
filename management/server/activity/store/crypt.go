package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// WARNING: This hardcoded IV is a security vulnerability and should NOT be used for new code.
// It is only kept for backward compatibility with legacy encrypted data.
// The LegacyEncrypt/LegacyDecrypt functions use this IV, which makes encryption deterministic
// and vulnerable to attacks. New code MUST use the Encrypt/Decrypt functions which use
// AES-GCM with random nonces.
//
// SECURITY NOTE: Using a hardcoded IV with CBC mode is insecure because:
// 1. The same plaintext encrypted with the same key will produce the same ciphertext
// 2. This allows pattern analysis and chosen-plaintext attacks
// 3. The IV should be random and unique for each encryption operation
//
// The new Encrypt/Decrypt functions use AES-GCM which generates a random nonce for each
// encryption, making it secure. Legacy functions are kept only for decrypting old data.
var iv = []byte{10, 22, 13, 79, 05, 8, 52, 91, 87, 98, 88, 98, 35, 25, 13, 05}

type FieldEncrypt struct {
	block cipher.Block
	gcm   cipher.AEAD
}

func GenerateKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	readableKey := base64.StdEncoding.EncodeToString(key)
	return readableKey, nil
}

func NewFieldEncrypt(key string) (*FieldEncrypt, error) {
	binKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(binKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ec := &FieldEncrypt{
		block: block,
		gcm:   gcm,
	}

	return ec, nil
}

// LegacyEncrypt encrypts using AES-CBC with a hardcoded IV.
// WARNING: This function is INSECURE and should only be used for backward compatibility.
// The hardcoded IV makes encryption deterministic and vulnerable to attacks.
// Use Encrypt() instead, which uses AES-GCM with random nonces.
//
// Security issues:
// - Hardcoded IV makes same plaintext produce same ciphertext
// - Vulnerable to pattern analysis and chosen-plaintext attacks
// - Should only be used to decrypt existing legacy data
func (ec *FieldEncrypt) LegacyEncrypt(payload string) string {
	plainText := pkcs5Padding([]byte(payload))
	cipherText := make([]byte, len(plainText))
	cbc := cipher.NewCBCEncrypter(ec.block, iv)
	cbc.CryptBlocks(cipherText, plainText)
	return base64.StdEncoding.EncodeToString(cipherText)
}

// Encrypt encrypts plaintext using AES-GCM with a random nonce.
// This is the secure method and should be used for all new encryptions.
// Each encryption uses a unique random nonce, making it secure against
// pattern analysis and chosen-plaintext attacks.
//
// Security features:
// - Uses AES-GCM (authenticated encryption)
// - Random nonce for each encryption (stored with ciphertext)
// - Provides authentication in addition to confidentiality
func (ec *FieldEncrypt) Encrypt(payload string) (string, error) {
	plaintext := []byte(payload)
	nonceSize := ec.gcm.NonceSize()

	nonce := make([]byte, nonceSize, len(plaintext)+nonceSize+ec.gcm.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := ec.gcm.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (ec *FieldEncrypt) LegacyDecrypt(data string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	cbc := cipher.NewCBCDecrypter(ec.block, iv)
	cbc.CryptBlocks(cipherText, cipherText)
	payload, err := pkcs5UnPadding(cipherText)
	if err != nil {
		return "", err
	}

	return string(payload), nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (ec *FieldEncrypt) Decrypt(data string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	nonceSize := ec.gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return "", errors.New("cipher text too short")
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err := ec.gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func pkcs5Padding(ciphertext []byte) []byte {
	padding := aes.BlockSize - len(ciphertext)%aes.BlockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}
func pkcs5UnPadding(src []byte) ([]byte, error) {
	srcLen := len(src)
	if srcLen == 0 {
		return nil, errors.New("input data is empty")
	}

	paddingLen := int(src[srcLen-1])
	if paddingLen == 0 || paddingLen > aes.BlockSize || paddingLen > srcLen {
		return nil, errors.New("invalid padding size")
	}

	// Verify that all padding bytes are the same
	for i := 0; i < paddingLen; i++ {
		if src[srcLen-1-i] != byte(paddingLen) {
			return nil, errors.New("invalid padding")
		}
	}

	return src[:srcLen-paddingLen], nil
}
