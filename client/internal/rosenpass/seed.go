package rosenpass

import (
	"crypto/sha256"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ratchetLabel domain-separates the expiry ratchet from other uses of the
// rosenpass output key.
const ratchetLabel = "netbird-rosenpass-expiry-ratchet"

// RatchetKey derives the successor preshared key from the previous Rosenpass
// output key. When a key expires without a completed renewal, both peers
// advance their last shared key by one ratchet step: the expired key is
// rotated out while both ends still converge on an identical, non-public
// replacement without communicating.
func RatchetKey(prev wgtypes.Key) wgtypes.Key {
	input := make([]byte, 0, len(ratchetLabel)+len(prev))
	input = append(input, ratchetLabel...)
	input = append(input, prev[:]...)
	return sha256.Sum256(input)
}

// DeterministicSeedKey derives a 32-byte WireGuard preshared key from a pair
// of peer public keys. Both peers, given the same key pair, produce the same
// output regardless of which side runs the function: the inputs are ordered
// lexicographically before concatenation.
//
// NetBird uses this value as the initial Rosenpass-side preshared key when no
// explicit account-level PSK is configured, so both peers converge on the same
// PSK before the first post-quantum handshake completes.
//
// The resulting key MUST NOT be treated as quantum-safe: it is deterministic
// from public keys and exists only to seed WireGuard until Rosenpass rotates
// in a real post-quantum PSK.
func DeterministicSeedKey(localKey, remoteKey string) (*wgtypes.Key, error) {
	lk := []byte(localKey)
	rk := []byte(remoteKey)
	if len(lk) < 16 || len(rk) < 16 {
		return nil, fmt.Errorf("rosenpass: peer keys must be at least 16 bytes (got local=%d, remote=%d)", len(lk), len(rk))
	}

	var keyInput []byte
	if localKey > remoteKey {
		keyInput = append(keyInput, lk[:16]...)
		keyInput = append(keyInput, rk[:16]...)
	} else {
		keyInput = append(keyInput, rk[:16]...)
		keyInput = append(keyInput, lk[:16]...)
	}

	key, err := wgtypes.NewKey(keyInput)
	if err != nil {
		return nil, fmt.Errorf("rosenpass: deterministic seed key: %w", err)
	}
	return &key, nil
}
