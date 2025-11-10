package encryption

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const nonceSize = 24

// A set of tools to encrypt/decrypt messages being sent through the Signal Exchange Service or Management Service
// These tools use Golang crypto package (Curve25519, XSalsa20 and Poly1305 to encrypt and authenticate)
// Wireguard keys are used for encryption

// Encrypt encrypts a message using local Wireguard private key and remote peer's public key.
// Security: This function generates a random nonce for each encryption operation, ensuring
// that the same plaintext encrypted multiple times produces different ciphertexts.
// The nonce is prepended to the ciphertext and will be extracted during decryption.
//
// The encryption uses:
// - Curve25519 for key exchange
// - XSalsa20 for encryption
// - Poly1305 for authentication
//
// This provides authenticated encryption, ensuring both confidentiality and integrity.
func Encrypt(msg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	// Security: Generate a unique random nonce for each encryption
	// This ensures that identical plaintexts produce different ciphertexts
	nonce, err := genNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	// Seal the message with the nonce prepended
	// The nonce is included in the output so it can be extracted during decryption
	return box.Seal(nonce[:], msg, nonce, toByte32(peerPublicKey), toByte32(privateKey)), nil
}

// Decrypt decrypts a message that has been encrypted by the remote peer using Wireguard private key and remote peer's public key.
// Security: This function extracts the nonce from the encrypted message (first 24 bytes) and uses it for decryption.
// The nonce is not generated randomly here - it must match the nonce used during encryption.
func Decrypt(encryptedMsg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	// Security: Validate encrypted message length before accessing nonce
	if len(encryptedMsg) < nonceSize {
		return nil, fmt.Errorf("invalid encrypted message length: message too short")
	}
	
	// Extract nonce from the first nonceSize bytes of the encrypted message
	// The nonce was prepended during encryption, so we extract it here
	var nonce [nonceSize]byte
	copy(nonce[:], encryptedMsg[:nonceSize])
	
	// Decrypt the remaining message (after the nonce) using the extracted nonce
	opened, ok := box.Open(nil, encryptedMsg[nonceSize:], &nonce, toByte32(peerPublicKey), toByte32(privateKey))
	if !ok {
		return nil, fmt.Errorf("failed to decrypt message from peer %s", peerPublicKey.String())
	}

	return opened, nil
}

// Generates nonce of size 24
func genNonce() (*[nonceSize]byte, error) {
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return &nonce, nil
}

// Converts Wireguard key to byte array of size 32 (a format used by the golang crypto package)
func toByte32(key wgtypes.Key) *[32]byte {
	return (*[32]byte)(&key)
}
