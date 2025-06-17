package server

import (
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

const (
	loginFilterSize = 100_000         // Size of the login filter map, making it large enough for a future
	filterTimeout   = 5 * time.Minute // Duration to secure the previous login information in the filter

	loggingLimit = 100
)

type loginFilter struct {
	mu     sync.RWMutex
	logged map[string]metahash
}

type metahash struct {
	hashes  map[string]struct{}
	counter int
	start   time.Time
}

func newLoginFilter() *loginFilter {
	return &loginFilter{
		logged: make(map[string]metahash, loginFilterSize),
	}
}

func (l *loginFilter) addLogin(wgPubKey, metaHash string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	mh, ok := l.logged[wgPubKey]
	if !ok {
		mh = metahash{
			hashes: make(map[string]struct{}, loggingLimit),
			start:  time.Now(),
		}
		l.logged[wgPubKey] = mh
	}
	mh.hashes[metaHash] = struct{}{}
	mh.counter++
	if mh.counter > loggingLimit && len(mh.hashes) > 1 {
		log.WithFields(log.Fields{
			"wgPubKey":                            wgPubKey,
			"number of different hashes":          len(mh.hashes),
			"elapsed time for number of attempts": time.Since(mh.start),
			"number of syncs":                     mh.counter,
		}).Info(mh.prepareHashes())

		delete(l.logged, wgPubKey)
	}
}

func (m *metahash) prepareHashes() string {
	var sb strings.Builder
	for hash := range m.hashes {
		sb.WriteString(hash)
		sb.WriteString(", ")
	}
	return sb.String()
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
