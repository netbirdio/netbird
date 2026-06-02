package grpc

import (
	"hash/fnv"
	"math"
	"sync"
	"time"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

const (
	reconnThreshold   = 5 * time.Minute
	baseBlockDuration = 10 * time.Minute // Duration for which a peer is banned after exceeding the reconnection limit
	reconnLimitForBan = 30               // Number of reconnections within the reconnTreshold that triggers a ban
	metaChangeLimit   = 3                // Number of reconnections with different metadata that triggers a ban of one peer
)

type lfConfig struct {
	reconnThreshold   time.Duration
	baseBlockDuration time.Duration
	reconnLimitForBan int
	metaChangeLimit   int
}

func initCfg() *lfConfig {
	return &lfConfig{
		reconnThreshold:   reconnThreshold,
		baseBlockDuration: baseBlockDuration,
		reconnLimitForBan: reconnLimitForBan,
		metaChangeLimit:   metaChangeLimit,
	}
}

type loginFilter struct {
	mu     sync.RWMutex
	cfg    *lfConfig
	logged map[string]*peerState
}

type peerState struct {
	currentHash           uint64
	sessionCounter        int
	sessionStart          time.Time
	lastSeen              time.Time
	isBanned              bool
	banLevel              int
	banExpiresAt          time.Time
	metaChangeCounter     int
	metaChangeWindowStart time.Time
}

func newLoginFilter() *loginFilter {
	return newLoginFilterWithCfg(initCfg())
}

func newLoginFilterWithCfg(cfg *lfConfig) *loginFilter {
	return &loginFilter{
		logged: make(map[string]*peerState),
		cfg:    cfg,
	}
}

func (l *loginFilter) allowLogin(wgPubKey string, metaHash uint64) bool {
	l.mu.RLock()
	defer func() {
		l.mu.RUnlock()
	}()
	state, ok := l.logged[wgPubKey]
	if !ok {
		return true
	}
	if state.isBanned && time.Now().Before(state.banExpiresAt) {
		return false
	}
	if metaHash != state.currentHash {
		if time.Now().Before(state.metaChangeWindowStart.Add(l.cfg.reconnThreshold)) && state.metaChangeCounter >= l.cfg.metaChangeLimit {
			return false
		}
	}
	return true
}

func (l *loginFilter) addLogin(wgPubKey string, metaHash uint64) {
	now := time.Now()
	l.mu.Lock()
	defer func() {
		l.mu.Unlock()
	}()

	state, ok := l.logged[wgPubKey]

	if !ok {
		l.logged[wgPubKey] = &peerState{
			currentHash:           metaHash,
			sessionCounter:        1,
			sessionStart:          now,
			lastSeen:              now,
			metaChangeWindowStart: now,
			metaChangeCounter:     1,
		}
		return
	}

	if state.isBanned && now.After(state.banExpiresAt) {
		state.isBanned = false
	}

	if state.banLevel > 0 && now.Sub(state.lastSeen) > (2*l.cfg.baseBlockDuration) {
		state.banLevel = 0
	}

	if metaHash != state.currentHash {
		if now.After(state.metaChangeWindowStart.Add(l.cfg.reconnThreshold)) {
			state.metaChangeWindowStart = now
			state.metaChangeCounter = 1
		} else {
			state.metaChangeCounter++
		}
		state.currentHash = metaHash
		state.sessionCounter = 1
		state.sessionStart = now
		state.lastSeen = now
		return
	}

	state.sessionCounter++
	if state.sessionCounter > l.cfg.reconnLimitForBan && now.Sub(state.sessionStart) < l.cfg.reconnThreshold {
		state.isBanned = true
		state.banLevel++

		backoffFactor := math.Pow(2, float64(state.banLevel-1))
		duration := time.Duration(float64(l.cfg.baseBlockDuration) * backoffFactor)
		state.banExpiresAt = now.Add(duration)

		state.sessionCounter = 0
		state.sessionStart = now
	}
	state.lastSeen = now
}

func metaHash(meta nbpeer.PeerSystemMeta, pubip string) uint64 {
	h := fnv.New64a()

	h.Write([]byte(meta.WtVersion))
	h.Write([]byte(meta.OSVersion))
	h.Write([]byte(meta.KernelVersion))
	h.Write([]byte(meta.Hostname))
	h.Write([]byte(meta.SystemSerialNumber))
	h.Write([]byte(pubip))

	macs := uint64(0)
	for _, na := range meta.NetworkAddresses {
		for _, r := range na.Mac {
			macs += uint64(r)
		}
	}

	return h.Sum64() + macs
}
