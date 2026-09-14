package uspfilter

import (
	"context"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
)

const (
	// defaultFragmentTimeout bounds how long a first-fragment verdict is kept
	// while the remaining fragments arrive. It mirrors the Linux IP reassembly
	// timeout (net.ipv4.ipfrag_time).
	defaultFragmentTimeout = 30 * time.Second
	// fragmentCleanupInterval is how often expired verdicts are purged.
	fragmentCleanupInterval = 10 * time.Second
	// defaultMaxFragmentEntries caps the number of concurrently tracked
	// fragmented datagrams. The table stays bounded because each datagram is a
	// single small entry regardless of how many fragments it is split into, and
	// the 13-bit IPv4 fragment-offset field limits any datagram to 64 KiB.
	defaultMaxFragmentEntries = 16384

	// EnvFragmentMaxEntries overrides defaultMaxFragmentEntries.
	EnvFragmentMaxEntries = "NB_FRAGMENT_MAX_ENTRIES"
)

// fragmentVerdict is the decision for a trailing (headerless) fragment.
type fragmentVerdict int

const (
	// fragmentDeny drops the fragment: no allowed first fragment is on record.
	fragmentDeny fragmentVerdict = iota
	// fragmentAllow passes the fragment: it belongs to an allowed datagram and
	// does not overlap the already-inspected transport header.
	fragmentAllow
	// fragmentOverlap drops the fragment and poisons its datagram: it overlaps
	// the transport header the ACL inspected (RFC 1858 §4, RFC 3128; RFC 5722
	// requires discarding the whole datagram on overlap for IPv6).
	fragmentOverlap
)

// fragmentKey identifies a fragmented datagram. It matches the RFC 791 / RFC
// 8200 reassembly key: source, destination, protocol and identification. The id
// is 32-bit to hold both the IPv4 (16-bit) and IPv6 (32-bit) identification.
type fragmentKey struct {
	srcIP netip.Addr
	dstIP netip.Addr
	id    uint32
	proto uint8
}

// fragmentEntry records the verdict of an allowed first fragment.
type fragmentEntry struct {
	// headerEndOctets is the offset, in 8-byte units, at which the first
	// fragment's payload ended. A trailing fragment starting before this
	// overlaps bytes the ACL already inspected and is rejected.
	headerEndOctets uint16
	// recordedAt is when the first fragment was accepted. The verdict expires a
	// fixed timeout later and is not refreshed, mirroring the kernel reassembly
	// timer so a trailing-fragment flood can't keep a datagram alive.
	recordedAt time.Time
}

// fragmentTracker records the ACL verdict of a datagram's first fragment so the
// remaining fragments, which carry no L4 header, can inherit the decision
// without reassembling the datagram. Only allowed first fragments are stored;
// anything that cannot be tied to an allowed, non-overlapping first fragment is
// dropped (fail closed).
type fragmentTracker struct {
	logger  *nblog.Logger
	mutex   sync.Mutex
	entries map[fragmentKey]fragmentEntry
	timeout time.Duration
	// maxEntries caps the table; atCapacity dedups the capacity warning until
	// the table drains below the cap again.
	maxEntries    int
	atCapacity    bool
	cleanupTicker *time.Ticker
	cancel        context.CancelFunc
}

func newFragmentTracker(logger *nblog.Logger) *fragmentTracker {
	ctx, cancel := context.WithCancel(context.Background())
	t := &fragmentTracker{
		logger:        logger,
		entries:       make(map[fragmentKey]fragmentEntry),
		timeout:       defaultFragmentTimeout,
		maxEntries:    fragmentMaxEntries(logger),
		cleanupTicker: time.NewTicker(fragmentCleanupInterval),
		cancel:        cancel,
	}
	go t.cleanupRoutine(ctx)
	return t
}

func fragmentMaxEntries(logger *nblog.Logger) int {
	v := os.Getenv(EnvFragmentMaxEntries)
	if v == "" {
		return defaultMaxFragmentEntries
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		logger.Warn2("invalid %s=%q, using default", EnvFragmentMaxEntries, v)
		return defaultMaxFragmentEntries
	}
	return n
}

// recordAllowed stores the verdict of an allowed first fragment. headerEndOctets
// is the first fragment's payload length in 8-byte units. When the table is full
// the record is dropped, which fails closed: the datagram's trailing fragments
// will be denied.
func (t *fragmentTracker) recordAllowed(key fragmentKey, headerEndOctets uint16) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.entries == nil {
		return
	}
	if _, ok := t.entries[key]; !ok && len(t.entries) >= t.maxEntries {
		if !t.atCapacity {
			t.atCapacity = true
			t.logger.Warn2("fragment verdict table at capacity (%d/%d): trailing fragments of new datagrams will be dropped",
				len(t.entries), t.maxEntries)
		}
		return
	}
	t.entries[key] = fragmentEntry{
		headerEndOctets: headerEndOctets,
		recordedAt:      time.Now(),
	}
}

// poison drops any recorded verdict for a datagram, so its later fragments are
// denied until a new allowed first fragment is recorded. Called on every
// offset-zero fragment to defeat offset-zero overlap rewrites (RFC 3128).
func (t *fragmentTracker) poison(key fragmentKey) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	delete(t.entries, key)
}

// verdict decides the fate of a trailing fragment at fragOffsetOctets (the IPv4
// fragment offset, in 8-byte units). A fragment overlapping the inspected
// header poisons the datagram: the entry is removed so all further fragments of
// that datagram are denied too.
func (t *fragmentTracker) verdict(key fragmentKey, fragOffsetOctets uint16) fragmentVerdict {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	entry, ok := t.entries[key]
	if !ok {
		return fragmentDeny
	}
	if time.Since(entry.recordedAt) > t.timeout {
		delete(t.entries, key)
		return fragmentDeny
	}
	if fragOffsetOctets < entry.headerEndOctets {
		delete(t.entries, key)
		return fragmentOverlap
	}
	return fragmentAllow
}

func (t *fragmentTracker) cleanupRoutine(ctx context.Context) {
	defer t.cleanupTicker.Stop()
	for {
		select {
		case <-t.cleanupTicker.C:
			t.cleanup()
		case <-ctx.Done():
			return
		}
	}
}

func (t *fragmentTracker) cleanup() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for key, entry := range t.entries {
		if time.Since(entry.recordedAt) > t.timeout {
			delete(t.entries, key)
		}
	}

	if len(t.entries) < t.maxEntries {
		t.atCapacity = false
	}
}

// Close stops the cleanup routine and releases resources.
func (t *fragmentTracker) Close() {
	t.cancel()

	t.mutex.Lock()
	t.entries = nil
	t.mutex.Unlock()
}
