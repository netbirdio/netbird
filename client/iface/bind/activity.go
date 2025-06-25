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
	Address      netip.AddrPort
	LastActivity atomic.Int64 // UnixNano timestamp
}

type ActivityRecorder struct {
	mu         sync.RWMutex
	peers      map[string]*PeerRecord         // publicKey to PeerRecord map
	addrToPeer map[netip.AddrPort]*PeerRecord // address to PeerRecord map
}

func NewActivityRecorder() *ActivityRecorder {
	return &ActivityRecorder{
		peers:      make(map[string]*PeerRecord),
		addrToPeer: make(map[netip.AddrPort]*PeerRecord),
	}
}

// GetLastActivities returns a snapshot of peer last activity
func (r *ActivityRecorder) GetLastActivities() map[string]time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()

	activities := make(map[string]time.Time, len(r.peers))
	for key, record := range r.peers {
		unixNano := record.LastActivity.Load()
		activities[key] = time.Unix(0, unixNano)
	}
	return activities
}

// UpsertAddress adds or updates the address for a publicKey
func (r *ActivityRecorder) UpsertAddress(publicKey string, address netip.AddrPort) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if pr, exists := r.peers[publicKey]; exists {
		delete(r.addrToPeer, pr.Address)
		pr.Address = address
	} else {
		record := &PeerRecord{
			Address: address,
		}
		record.LastActivity.Store(time.Now().Unix())
		r.peers[publicKey] = record
	}

	r.addrToPeer[address] = r.peers[publicKey]
}

func (r *ActivityRecorder) Remove(publicKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if record, exists := r.peers[publicKey]; exists {
		delete(r.addrToPeer, record.Address)
		delete(r.peers, publicKey)
	}
}

// Record updates LastActivity for the given address using atomic store
func (r *ActivityRecorder) Record(address netip.AddrPort) {
	r.mu.RLock()
	record, ok := r.addrToPeer[address]
	r.mu.RUnlock()
	if !ok {
		log.Warnf("could not find record for address %s", address)
		return
	}

	now := monotime.Now()
	if now-record.LastActivity.Load() < saveFrequency {
		return
	}

	record.LastActivity.Store(now)
}
