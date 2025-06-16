package server

import (
	"strings"
	"sync"
	"time"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

const (
	loginFilterSize = 100_000         // Size of the login filter map, making it large enough for a future
	filterTimeout   = 5 * time.Minute // Duration to secure the previous login information in the filter
)

type loginFilter struct {
	mu     sync.RWMutex
	logged map[string]metahash
}

type metahash struct {
	hash      string
	lastlogin time.Time
}

func newLoginFilter() *loginFilter {
	return &loginFilter{
		logged: make(map[string]metahash, loginFilterSize),
	}
}

func (l *loginFilter) addLogin(wgPubKey, metaHash string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logged[wgPubKey] = metahash{
		hash:      metaHash,
		lastlogin: time.Now(),
	}
}

func (l *loginFilter) allowLogin(wgPubKey, metaHash string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if loggedMetaHash, ok := l.logged[wgPubKey]; ok {
		return loggedMetaHash.hash == metaHash && time.Since(loggedMetaHash.lastlogin) < filterTimeout
	}
	return true
}

func (l *loginFilter) removeLogin(wgPubKey string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.logged, wgPubKey)
}

func metaHash(meta nbpeer.PeerSystemMeta) string {
	estimatedSize := len(meta.WtVersion) + len(meta.OSVersion) + len(meta.KernelVersion) + len(meta.Hostname)

	var b strings.Builder
	b.Grow(estimatedSize)

	b.WriteString(meta.WtVersion)
	b.WriteString(meta.OSVersion)
	b.WriteString(meta.KernelVersion)
	b.WriteString(meta.Hostname)

	return b.String()
}
