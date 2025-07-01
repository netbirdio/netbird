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

	loggingLimitOnePeer    = 30
	loggingTresholdOnePeer = 5 * time.Minute
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
	}
	mh.hashes[metaHash] = struct{}{}
	mh.counter++
	if mh.counter >= loggingLimit && mh.counter%loggingLimit == 0 && len(mh.hashes) > 1 {
		log.WithFields(log.Fields{
			"wgPubKey":                            wgPubKey,
			"number of different hashes":          len(mh.hashes),
			"elapsed time for number of attempts": time.Since(mh.start),
			"number of syncs":                     mh.counter,
		}).Info(mh.prepareHashes())
	} else if mh.counter%loggingLimitOnePeer == 0 && time.Since(mh.start) > loggingTresholdOnePeer && len(mh.hashes) == 1 {
		log.WithFields(log.Fields{
			"wgPubKey":                            wgPubKey,
			"elapsed time for number of attempts": time.Since(mh.start),
			"number of syncs":                     mh.counter,
		}).Info(mh.prepareHashes())
		mh.start = time.Now()
	}
	l.logged[wgPubKey] = mh
}

func (m *metahash) prepareHashes() string {
	var sb strings.Builder
	for hash := range m.hashes {
		sb.WriteString(hash)
		sb.WriteString(", ")
	}
	return sb.String()
}

func metaHash(meta nbpeer.PeerSystemMeta, pubip string) string {
	mac := getMacAddress(meta.NetworkAddresses)
	estimatedSize := len(meta.WtVersion) + len(meta.OSVersion) + len(meta.KernelVersion) + len(meta.Hostname) + len(meta.SystemSerialNumber) +
		len(pubip) + len(mac) + 6

	var b strings.Builder
	b.Grow(estimatedSize)

	b.WriteString(meta.WtVersion)
	b.WriteByte('|')
	b.WriteString(meta.OSVersion)
	b.WriteByte('|')
	b.WriteString(meta.KernelVersion)
	b.WriteByte('|')
	b.WriteString(meta.Hostname)
	b.WriteByte('|')
	b.WriteString(meta.SystemSerialNumber)
	b.WriteByte('|')
	b.WriteString(pubip)
	b.WriteByte('|')
	b.WriteString(mac)

	return b.String()
}

func getMacAddress(nas []nbpeer.NetworkAddress) string {
	if len(nas) == 0 {
		return ""
	}
	macs := make([]string, 0, len(nas))
	for _, na := range nas {
		macs = append(macs, na.Mac)
	}
	return strings.Join(macs, "/")
}
