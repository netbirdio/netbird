package certproof

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// helperQuietPeriod is how long a user whose helper proved nothing is not asked again
// for the same CAs. On macOS each helper run may show a keychain prompt, so retrying on
// every collection would put up a new one each time the user ignored or denied the last.
const helperQuietPeriod = time.Hour

// helperBackoff remembers, per user and set of CAs asked about, until when the helper
// is not launched again because its last run proved nothing.
type helperBackoff struct {
	mu    sync.Mutex
	until map[string]time.Time
}

var userHelperBackoff = &helperBackoff{until: map[string]time.Time{}}

// allow reports whether the helper may be launched for key now.
func (b *helperBackoff) allow(key string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !now.Before(b.until[key])
}

// record stores the outcome of a helper run for key: one that proved something clears
// the back-off, one that proved nothing starts it.
func (b *helperBackoff) record(key string, proven bool, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if proven {
		delete(b.until, key)
		return
	}
	b.until[key] = now.Add(helperQuietPeriod)
}

// helperBackoffKey identifies a user and the CAs the challenges accept, leaving out the
// nonces, which rotate without changing what the user is asked to prove.
func helperBackoffKey(user string, challenges []*proto.CertificateChallenge) string {
	h := sha256.New()
	h.Write([]byte(user))
	for _, challenge := range challenges {
		h.Write([]byte{0})
		for _, ca := range challenge.GetCaCertificates() {
			h.Write([]byte{1})
			h.Write([]byte(ca))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
