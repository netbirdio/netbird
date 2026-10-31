package server

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/shared/peerauth"
)

// proofCacheSweepInterval is how often expired verifications are dropped from the cache.
const proofCacheSweepInterval = 10 * time.Minute

var (
	errPeerAuthRequired = errors.New("peer auth credentials required")
	errPeerIDMismatch   = errors.New("token is bound to another peer")
)

// PeerAuthConfig configures the check of the token bound to the peer keys. Without keys Signal
// ignores the credentials and serves every peer as a legacy one.
type PeerAuthConfig struct {
	Keys peerauth.TokenKeys
	// Hostnames, if set, are the only hostnames accepted in proofs.
	Hostnames []string
	// Required refuses peers that present no credentials.
	Required bool
	// CheckTime bounds the proof timestamp to peerauth.DefaultSkew from Signal's clock. Off, a
	// proof is valid as long as its token, so peer clocks need not be in sync.
	CheckTime bool
}

// peerAuth verifies the credentials sent with ConnectStream and Send.
type peerAuth struct {
	verifier *peerauth.Verifier
	required bool
	cache    *proofCache
}

// newPeerAuth returns nil when no keys are configured.
func newPeerAuth(cfg PeerAuthConfig) (*peerAuth, error) {
	if len(cfg.Keys.HMAC) == 0 && len(cfg.Keys.Ed25519) == 0 {
		if cfg.Required {
			return nil, errors.New("peer auth required without keys")
		}
		return nil, nil //nolint:nilnil // no keys: credentials are ignored
	}
	if _, err := cfg.Keys.Mode(); err != nil {
		return nil, err
	}
	verifier := &peerauth.Verifier{
		Service:   peerauth.ServiceSignal,
		Keys:      cfg.Keys,
		Hostnames: cfg.Hostnames,
	}
	if cfg.CheckTime {
		verifier.Skew = peerauth.DefaultSkew
	}
	return &peerAuth{
		verifier: verifier,
		required: cfg.Required,
		cache:    newProofCache(),
	}, nil
}

// start sweeps the proof cache until the returned stop is called; stop waits for the sweeper.
func (a *peerAuth) start() (stop func()) {
	if a == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go a.cache.sweepLoop(ctx, proofCacheSweepInterval, done)
	return func() {
		cancel()
		<-done
	}
}

// authenticate reports whether the call carries valid credentials for peerKey. A call without
// credentials is a legacy one, refused only when they are required; invalid ones are refused.
func (a *peerAuth) authenticate(md metadata.MD, peerKey string) (bool, error) {
	if a == nil {
		return false, nil
	}
	token, proof, err := peerauth.FromMetadata(md)
	switch {
	case errors.Is(err, peerauth.ErrMissingCredentials) && !a.required:
		return false, nil
	case errors.Is(err, peerauth.ErrMissingCredentials):
		return false, refused(peerKey, errPeerAuthRequired)
	case err != nil:
		return false, refused(peerKey, err)
	}

	now := time.Now()
	digest := credentialsDigest(token, proof)
	if a.cache.valid(peerKey, digest, now) {
		return true, nil
	}
	if err := a.verify(peerKey, token, proof, digest, now); err != nil {
		return false, refused(peerKey, err)
	}
	return true, nil
}

func (a *peerAuth) verify(peerKey string, token []byte, proof peerauth.Proof, digest [sha256.Size]byte, now time.Time) error {
	t, err := a.verifier.Verify(token, proof, now)
	if err != nil {
		return err
	}
	if t.WGPub.String() != peerKey {
		return errPeerIDMismatch
	}
	expiry := t.Expiry
	if skew := a.verifier.Skew; skew > 0 && proof.Timestamp.Add(skew).Before(expiry) {
		expiry = proof.Timestamp.Add(skew)
	}
	a.cache.store(peerKey, digest, expiry)
	return nil
}

// credentialsDigest covers every presented byte a verification depends on, so a cache hit stands
// for exactly the credentials that were verified.
func credentialsDigest(token []byte, p peerauth.Proof) [sha256.Size]byte {
	h := sha256.New()
	for _, field := range [][]byte{token, []byte(p.Hostname), p.Signature} {
		_ = binary.Write(h, binary.BigEndian, uint32(len(field)))
		h.Write(field)
	}
	_ = binary.Write(h, binary.BigEndian, p.Timestamp.Unix())
	var d [sha256.Size]byte
	h.Sum(d[:0])
	return d
}

// proofCache keeps the last verified credentials of each peer, so a proof reused within its window
// is verified once. One entry per peer: a newer proof replaces the older one.
type proofCache struct {
	mu      sync.Mutex
	entries map[string]proofCacheEntry
}

type proofCacheEntry struct {
	digest [sha256.Size]byte
	expiry time.Time
}

func newProofCache() *proofCache {
	return &proofCache{entries: make(map[string]proofCacheEntry)}
}

func (c *proofCache) valid(peerKey string, digest [sha256.Size]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[peerKey]
	return ok && e.digest == digest && now.Before(e.expiry)
}

func (c *proofCache) store(peerKey string, digest [sha256.Size]byte, expiry time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[peerKey] = proofCacheEntry{digest: digest, expiry: expiry}
}

// sweep drops expired entries, so peers that went away do not stay in memory.
func (c *proofCache) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if !now.Before(e.expiry) {
			delete(c.entries, k)
		}
	}
}

func (c *proofCache) sweepLoop(ctx context.Context, interval time.Duration, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			c.sweep(now)
		}
	}
}

// refused logs refused credentials at debug when a peer repeats them on every retry (none, or an
// expired token) and at info when they do not verify.
func refused(peerKey string, err error) error {
	switch {
	case errors.Is(err, errPeerAuthRequired), errors.Is(err, peerauth.ErrTokenExpired):
		log.Debugf("refused peer [%s]: %v", peerKey, err)
	case errors.Is(err, peerauth.ErrStaleProof):
		log.Infof("refused peer [%s], check the peer clock: %v", peerKey, err)
	default:
		log.Infof("refused peer [%s]: %v", peerKey, err)
	}
	return status.Error(codes.Unauthenticated, err.Error())
}

// legacyTakeoverError refuses a legacy call that claims a peer currently connected with credentials.
func legacyTakeoverError(peerKey string) error {
	err := fmt.Errorf("peer [%s] is connected with peer auth credentials", peerKey)
	log.Infof("refused legacy peer: %v", err)
	return status.Error(codes.PermissionDenied, err.Error())
}
