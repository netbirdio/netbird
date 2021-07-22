package common

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// As set of tools to encrypt/decrypt messages being sent through the Signal Exchange Service.
// We want to make sure that the Connection Candidates and other irrelevant (to the Signal Exchange)
// information can't be read anywhere else but the Peer the message is being sent to.
// These tools use Golang crypto package (Curve25519, XSalsa20 and Poly1305 to encrypt and authenticate)
// Wireguard keys are used for encryption

// Encrypt encrypts a message using local Wireguard private key and remote peer's public key.
func Encrypt(msg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	nonce, err := genNonce()
	if err != nil {
		return nil, err
	}
	return box.Seal(nonce[:], msg, nonce, toByte32(peerPublicKey), toByte32(privateKey)), nil
}

// Decrypt decrypts a message that has been encrypted by the remote peer using Wireguard private key and remote peer's public key.
func Decrypt(encryptedMsg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	nonce, err := genNonce()
	if err != nil {
		return nil, err
	}
	copy(nonce[:], encryptedMsg[:24])
	opened, ok := box.Open(nil, encryptedMsg[24:], nonce, toByte32(peerPublicKey), toByte32(privateKey))
	if !ok {
		return nil, fmt.Errorf("failed to decrypt message from peer %s", peerPublicKey.String())
	}

	return opened, nil
}

// Generates nonce of size 24
func genNonce() (*[24]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return &nonce, nil
}

// Converts Wireguard key to byte array of size 32 (a format used by the golang crypto package)
func toByte32(key wgtypes.Key) *[32]byte {
	return (*[32]byte)(&key)
}
