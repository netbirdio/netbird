package server

import (
	"hash/fnv"
	"sync"
	"time"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

const (
	filterTimeout = 5 * time.Minute // Duration to secure the previous login information in the filter

	reconnTreshold    = 5 * time.Minute
	blockDuration     = 10 * time.Minute // Duration for which a user is banned after exceeding the reconnection limit
	reconnLimitForBan = 30               // Number of reconnections within the reconnTrashold that triggers a ban
)

type config struct {
	filterTimeout     time.Duration
	reconnTreshold    time.Duration
	blockDuration     time.Duration
	reconnLimitForBan int
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
		filterTimeout:     filterTimeout,
		reconnTreshold:    reconnTreshold,
		blockDuration:     blockDuration,
		reconnLimitForBan: reconnLimitForBan,
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
	if mh.counter > l.cfg.reconnLimitForBan && mh.lastSeen.Sub(mh.firstLogin) < l.cfg.reconnTreshold {
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
	if mh.hash != metaHash && time.Since(mh.lastSeen) < l.cfg.filterTimeout {
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

	if len(meta.NetworkAddresses) != 0 {
		for _, na := range meta.NetworkAddresses {
			h.Write([]byte(na.Mac))
		}
	}

	h.Write([]byte(meta.WtVersion))
	h.Write([]byte(meta.OSVersion))
	h.Write([]byte(meta.KernelVersion))
	h.Write([]byte(meta.Hostname))
	h.Write([]byte(meta.SystemSerialNumber))
	h.Write([]byte(pubip))

	return h.Sum64()
}
