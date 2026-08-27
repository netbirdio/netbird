package crypt

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestDecrypt_Fallback(t *testing.T) {
	key, err := GenerateKey()
	assert.NoError(t, err)

	ec, err := NewFieldEncrypt(key)
	assert.NoError(t, err)

	plaintext := "this-is-not-base64-!!!"
	payload, err := ec.Decrypt(plaintext)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, payload)
}
