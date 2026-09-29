package encryption

import (
	"fmt"
	"sync"

	pb "github.com/golang/protobuf/proto" //nolint
	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// SharedKeyCache encrypts and decrypts messages for one local private key, deriving
// the box shared key once per remote public key instead of once per message.
//
// The shared key is a pure function of the two keys, so a cached entry never goes
// stale: a different remote key is a different entry, and a different local key
// needs a different cache. Entries are only dropped to stay under maxSharedKeys.
// Every message still uses its own random nonce.
//
// The cached values are secret key material, as sensitive as the private key.
type SharedKeyCache struct {
	privateKey wgtypes.Key
	limit      int

	mu     sync.RWMutex
	keys   map[wgtypes.Key]*[32]byte
	closed bool
}

// NewSharedKeyCache returns a cache for messages sent and received with privateKey.
func NewSharedKeyCache(privateKey wgtypes.Key) *SharedKeyCache {
	return &SharedKeyCache{
		privateKey: privateKey,
		limit:      maxSharedKeys,
		keys:       make(map[wgtypes.Key]*[32]byte),
	}
}

// Encrypt encrypts msg for peerPublicKey. It is safe for concurrent use.
func (c *SharedKeyCache) Encrypt(msg []byte, peerPublicKey wgtypes.Key) ([]byte, error) {
	nonce, err := genNonce()
	if err != nil {
		return nil, err
	}
	return box.SealAfterPrecomputation(nonce[:], msg, nonce, c.sharedKey(peerPublicKey)), nil
}

// Decrypt decrypts a message that peerPublicKey encrypted for this cache's private
// key. It is safe for concurrent use.
func (c *SharedKeyCache) Decrypt(encryptedMsg []byte, peerPublicKey wgtypes.Key) ([]byte, error) {
	if len(encryptedMsg) < nonceSize {
		return nil, fmt.Errorf("invalid encrypted message length")
	}

	var nonce [nonceSize]byte
	copy(nonce[:], encryptedMsg[:nonceSize])

	shared, cached := c.cached(peerPublicKey)
	if !cached {
		shared = c.derive(peerPublicKey)
	}

	opened, ok := box.OpenAfterPrecomputation(nil, encryptedMsg[nonceSize:], &nonce, shared)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt message from peer %s", peerPublicKey.String())
	}

	// The sender key of an incoming message is not authenticated until it opens, so
	// only a key that produced a valid message is cached. Forged senders cannot fill
	// the cache or evict real peers.
	if !cached {
		c.store(peerPublicKey, shared)
	}
	return opened, nil
}

// EncryptMessage marshals message and encrypts it for peerPublicKey.
func (c *SharedKeyCache) EncryptMessage(peerPublicKey wgtypes.Key, message pb.Message) ([]byte, error) {
	body, err := pb.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}
	return c.Encrypt(body, peerPublicKey)
}

// DecryptMessage decrypts a message from peerPublicKey and unmarshals it into message.
func (c *SharedKeyCache) DecryptMessage(peerPublicKey wgtypes.Key, encryptedMessage []byte, message pb.Message) error {
	body, err := c.Decrypt(encryptedMessage, peerPublicKey)
	if err != nil {
		return err
	}
	if err := pb.Unmarshal(body, message); err != nil {
		return fmt.Errorf("unmarshal message from peer %s: %w", peerPublicKey.String(), err)
	}
	return nil
}

// Close drops every cached shared key and stops caching new ones. Encrypt and
// Decrypt keep working afterwards by deriving the key for each message.
func (c *SharedKeyCache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	clear(c.keys)
}

func (c *SharedKeyCache) sharedKey(peerPublicKey wgtypes.Key) *[32]byte {
	if shared, ok := c.cached(peerPublicKey); ok {
		return shared
	}

	shared := c.derive(peerPublicKey)
	c.store(peerPublicKey, shared)
	return shared
}

func (c *SharedKeyCache) cached(peerPublicKey wgtypes.Key) (*[32]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	shared, ok := c.keys[peerPublicKey]
	return shared, ok
}

// derive computes the shared key outside the lock: two goroutines racing on a new
// peer compute the same value, and holding the lock would serialise the x25519 work
// this cache avoids.
func (c *SharedKeyCache) derive(peerPublicKey wgtypes.Key) *[32]byte {
	shared := new([32]byte)
	box.Precompute(shared, toByte32(peerPublicKey), toByte32(c.privateKey))
	return shared
}

func (c *SharedKeyCache) store(peerPublicKey wgtypes.Key, shared *[32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if len(c.keys) >= c.limit {
		// Map iteration order is random, so this evicts an arbitrary entry.
		for k := range c.keys {
			delete(c.keys, k)
			break
		}
	}
	c.keys[peerPublicKey] = shared
}
