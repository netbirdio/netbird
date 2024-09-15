package sqlite

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

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

func (ec *FieldEncrypt) LegacyEncrypt(payload string) string {
	plainText := pkcs5Padding([]byte(payload))
	cipherText := make([]byte, len(plainText))
	cbc := cipher.NewCBCEncrypter(ec.block, iv)
	cbc.CryptBlocks(cipherText, plainText)
	return base64.StdEncoding.EncodeToString(cipherText)
}

// Encrypt encrypts plaintext using AES-GCM
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
