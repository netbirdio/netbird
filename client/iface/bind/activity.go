package bind

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/monotime"
)

const (
	saveFrequency = int64(5 * time.Second)
)

type PeerRecord struct {
	PublicKey    string
	Address      netip.AddrPort
	LastActivity atomic.Int64 // UnixNano timestamp
}

type ActivityRecorder struct {
	mu         sync.RWMutex
	peers      map[string]*PeerRecord         // publicKey to PeerRecord map
	addrToPeer map[netip.AddrPort]*PeerRecord // address to PeerRecord map
	// onActivity, if set, is invoked once per saveFrequency-window per
	// peer when transport activity is observed. Used by the engine's
	// connMgr to fast-path ICE re-attach for peers that fell back to
	// relay-only on iceTimeout (Codex review 2026-05-05). Rate-limited
	// piggybacks the existing CAS to avoid a hot-path allocation.
	onActivity func(pubKey string)
}

func NewActivityRecorder() *ActivityRecorder {
	return &ActivityRecorder{
		peers:      make(map[string]*PeerRecord),
		addrToPeer: make(map[netip.AddrPort]*PeerRecord),
	}
}

// SetOnActivity registers a callback invoked at most once per
// saveFrequency (5s) per peer when transport activity is recorded.
// Pass nil to clear. Safe to call before the recorder starts seeing
// traffic.
func (r *ActivityRecorder) SetOnActivity(cb func(pubKey string)) {
	r.mu.Lock()
	r.onActivity = cb
	r.mu.Unlock()
}

// GetLastActivities returns a snapshot of peer last activity
func (r *ActivityRecorder) GetLastActivities() map[string]monotime.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()

	activities := make(map[string]monotime.Time, len(r.peers))
	for key, record := range r.peers {
		monoTime := record.LastActivity.Load()
		activities[key] = monotime.Time(monoTime)
	}
	return activities
}

// UpsertAddress adds or updates the address for a publicKey
func (r *ActivityRecorder) UpsertAddress(publicKey string, address netip.AddrPort) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var record *PeerRecord
	record, exists := r.peers[publicKey]
	if exists {
		delete(r.addrToPeer, record.Address)
		record.Address = address
	} else {
		record = &PeerRecord{
			PublicKey: publicKey,
			Address:   address,
		}
		record.LastActivity.Store(int64(monotime.Now()))
		r.peers[publicKey] = record
	}

	r.addrToPeer[address] = record
}

func (r *ActivityRecorder) Remove(publicKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if record, exists := r.peers[publicKey]; exists {
		delete(r.addrToPeer, record.Address)
		delete(r.peers, publicKey)
	}
}

// record updates LastActivity for the given address using atomic store
func (r *ActivityRecorder) record(address netip.AddrPort) {
	r.mu.RLock()
	record, ok := r.addrToPeer[address]
	cb := r.onActivity
	r.mu.RUnlock()
	if !ok {
		log.Warnf("could not find record for address %s", address)
		return
	}

	now := int64(monotime.Now())
	last := record.LastActivity.Load()
	if now-last < saveFrequency {
		return
	}

	if record.LastActivity.CompareAndSwap(last, now) && cb != nil {
		// Fire only on the actual save edge (CAS success). Prevents
		// duplicate events when many goroutines race on the same packet
		// burst. Callback runs synchronously on the WG read/write
		// goroutine -- handler MUST be cheap or self-defer to its own
		// goroutine.
		cb(record.PublicKey)
	}
}
