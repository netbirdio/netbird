package server

import (
	"hash/fnv"
	"sync"
	"time"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

const (
	filterTimeout = 5 * time.Minute // Duration to secure the previous login information in the filter

	reconnThreshold         = 5 * time.Minute
	blockDuration           = 10 * time.Minute // Duration for which a peer is banned after exceeding the reconnection limit
	reconnLimitForBan       = 30               // Number of reconnections within the reconnTreshold that triggers a ban
	differentMetaReconnects = 3                // Number of reconnections with different metadata that triggers a ban of one peer
)

type config struct {
	filterTimeout           time.Duration
	reconnThreshold         time.Duration
	blockDuration           time.Duration
	reconnLimitForBan       int
	differentMetaReconnects int
}

type loginFilter struct {
	mu     sync.RWMutex
	cfg    *config
	logged map[string]metahash
}

type metahash struct {
	hash       uint64
	counter    int
	banned     bool
	firstLogin time.Time
	lastSeen   time.Time
}

func initCfg() *config {
	return &config{
		filterTimeout:           filterTimeout,
		reconnThreshold:         reconnThreshold,
		blockDuration:           blockDuration,
		reconnLimitForBan:       reconnLimitForBan,
		differentMetaReconnects: differentMetaReconnects,
	}
}

func newLoginFilter() *loginFilter {
	return newLoginFilterWithCfg(initCfg())
}

func newLoginFilterWithCfg(cfg *config) *loginFilter {
	return &loginFilter{
		logged: make(map[string]metahash),
		cfg:    cfg,
	}
}

func (l *loginFilter) addLogin(wgPubKey string, metaHash uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	mh, ok := l.logged[wgPubKey]
	if !ok || mh.banned {
		mh = metahash{
			hash:       metaHash,
			firstLogin: time.Now(),
		}
	}
	mh.counter++
	mh.hash = metaHash
	mh.lastSeen = time.Now()
	if mh.counter > l.cfg.reconnLimitForBan && mh.lastSeen.Sub(mh.firstLogin) < l.cfg.reconnThreshold {
		mh.banned = true
	}
	l.logged[wgPubKey] = mh
}

func (l *loginFilter) allowLogin(wgPubKey string, metaHash uint64) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	mh, ok := l.logged[wgPubKey]
	if !ok {
		return true
	}
	if mh.banned && time.Since(mh.lastSeen) < l.cfg.blockDuration {
		return false
	}
	if mh.hash != metaHash && time.Since(mh.lastSeen) < l.cfg.filterTimeout && mh.counter > l.cfg.differentMetaReconnects {
		return false
	}
	return true
}

func (l *loginFilter) removeLogin(wgPubKey string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.logged, wgPubKey)
}

func metaHash(meta nbpeer.PeerSystemMeta, pubip string) uint64 {
	h := fnv.New64a()

	h.Write([]byte(meta.WtVersion))
	h.Write([]byte(meta.OSVersion))
	h.Write([]byte(meta.KernelVersion))
	h.Write([]byte(meta.Hostname))
	h.Write([]byte(meta.SystemSerialNumber))
	h.Write([]byte(pubip))

	return h.Sum64()
}
