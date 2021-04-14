package signal

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// As set of tools to encrypt/decrypt messages being sent through the Signal Exchange Service.
// We want to make sure that the Connection Candidates and other irrelevant (to the Signal Exchange) information can't be read anywhere else but the Peer the message is being sent to.
// These tools use Golang crypto package (Curve25519, XSalsa20 and Poly1305 to encrypt and authenticate)
// Wireguard keys are used for encryption

// Encrypts a message using local Wireguard private key and remote peer's public key.
func EncryptMessage(msg []byte, privateKey wgtypes.Key, remotePubKey wgtypes.Key) ([]byte, error) {
	nonce, err := genNonce()
	if err != nil {
		return nil, err
	}

	return box.Seal(nil, msg, nonce, toByte32(remotePubKey), toByte32(privateKey)), nil
}

// Decrypts a message that has been encrypted by the remote peer using Wireguard private key and remote peer's public key.
func DecryptMessage(encryptedMsg []byte, privateKey wgtypes.Key, remotePubKey wgtypes.Key) ([]byte, error) {
	nonce, err := genNonce()
	if err != nil {
		return nil, err
	}

	opened, ok := box.Open(nil, encryptedMsg, nonce, toByte32(remotePubKey), toByte32(privateKey))
	if !ok {
		return nil, fmt.Errorf("failed to decrypt message from peer %s", remotePubKey.String())
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
