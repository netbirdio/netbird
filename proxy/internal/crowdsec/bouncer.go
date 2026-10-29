// Package crowdsec provides a CrowdSec stream bouncer that maintains a local
// decision cache for IP reputation checks.
package crowdsec

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/restrict"
)

// Bouncer wraps a CrowdSec StreamBouncer, maintaining a local cache of
// active decisions for fast IP lookups. It implements restrict.CrowdSecChecker.
type Bouncer struct {
	mu       sync.RWMutex
	ips      map[netip.Addr]*restrict.CrowdSecDecision
	prefixes map[netip.Prefix]*restrict.CrowdSecDecision
	ready    atomic.Bool

	apiURL         string
	apiKey         string
	tickerInterval time.Duration
	logger         *log.Entry

	// lifeMu protects cancel and done from concurrent Start/Stop calls.
	lifeMu sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// compile-time check
var _ restrict.CrowdSecChecker = (*Bouncer)(nil)

// NewBouncer creates a bouncer but does not start the stream.
func NewBouncer(apiURL, apiKey string, logger *log.Entry) *Bouncer {
	return &Bouncer{
		apiURL:   apiURL,
		apiKey:   apiKey,
		logger:   logger,
		ips:      make(map[netip.Addr]*restrict.CrowdSecDecision),
		prefixes: make(map[netip.Prefix]*restrict.CrowdSecDecision),
	}
}

// Start launches the background goroutine that streams decisions from the
// CrowdSec LAPI. The stream runs until Stop is called or ctx is cancelled.
func (b *Bouncer) Start(ctx context.Context) error {
	interval := b.tickerInterval
	if interval == 0 {
		interval = 10 * time.Second
	}
	stream := &csbouncer.StreamBouncer{
		APIKey:              b.apiKey,
		APIUrl:              b.apiURL,
		TickerInterval:      interval.String(),
		UserAgent:           "netbird-proxy/1.0",
		Scopes:              []string{"ip", "range"},
		RetryInitialConnect: true,
	}

	b.logger.Infof("connecting to CrowdSec LAPI at %s", b.apiURL)

	if err := stream.Init(); err != nil {
		return err
	}

	// Reset state from any previous run.
	b.mu.Lock()
	b.ips = make(map[netip.Addr]*restrict.CrowdSecDecision)
	b.prefixes = make(map[netip.Prefix]*restrict.CrowdSecDecision)
	b.mu.Unlock()
	b.ready.Store(false)

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	b.lifeMu.Lock()
	if b.cancel != nil {
		b.lifeMu.Unlock()
		cancel()
		return errors.New("bouncer already started")
	}
	b.cancel = cancel
	b.done = done
	b.lifeMu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := stream.Run(ctx); err != nil && ctx.Err() == nil {
			b.logger.Errorf("CrowdSec stream ended: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		b.consumeStream(ctx, stream)
	}()

	go func() {
		wg.Wait()
		close(done)
	}()

	return nil
}

// Stop cancels the stream and waits for all goroutines to finish.
func (b *Bouncer) Stop() {
	b.lifeMu.Lock()
	cancel := b.cancel
	done := b.done
	b.cancel = nil
	b.lifeMu.Unlock()

	if cancel != nil {
		cancel()
		<-done
	}
}

// Ready returns true after the first batch of decisions has been processed.
func (b *Bouncer) Ready() bool {
	return b.ready.Load()
}

// CheckIP looks up addr in the local decision cache. Returns nil if no
// active decision exists for the address.
//
// Prefix lookups are O(1): instead of scanning all stored prefixes, we
// probe the map for every possible containing prefix of the address
// (at most 33 for IPv4, 129 for IPv6).
func (b *Bouncer) CheckIP(addr netip.Addr) *restrict.CrowdSecDecision {
	addr = addr.Unmap()

	b.mu.RLock()
	defer b.mu.RUnlock()

	if d, ok := b.ips[addr]; ok {
		return d
	}

	maxBits := 32
	if addr.Is6() {
		maxBits = 128
	}
	// Walk from most-specific to least-specific prefix so the narrowest
	// matching decision wins when ranges overlap.
	for bits := maxBits; bits >= 0; bits-- {
		prefix := netip.PrefixFrom(addr, bits).Masked()
		if d, ok := b.prefixes[prefix]; ok {
			return d
		}
	}

	return nil
}

func (b *Bouncer) consumeStream(ctx context.Context, stream *csbouncer.StreamBouncer) {
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case resp, ok := <-stream.Stream:
			if !ok {
				return
			}
			b.mu.Lock()
			b.applyDeleted(resp.Deleted)
			b.applyNew(resp.New)
			b.mu.Unlock()

			if first {
				b.ready.Store(true)
				b.logger.Info("CrowdSec bouncer synced initial decisions")
				first = false
			}
		}
	}
}

func (b *Bouncer) applyDeleted(decisions []*models.Decision) {
	for _, d := range decisions {
		if d.Value == nil || d.Scope == nil {
			continue
		}
		value := *d.Value

		if strings.ToLower(*d.Scope) == "range" || strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				b.logger.Debugf("skip unparsable CrowdSec range deletion %q: %v", value, err)
				continue
			}
			prefix = normalizePrefix(prefix)
			delete(b.prefixes, prefix)
		} else {
			addr, err := netip.ParseAddr(value)
			if err != nil {
				b.logger.Debugf("skip unparsable CrowdSec IP deletion %q: %v", value, err)
				continue
			}
			delete(b.ips, addr.Unmap())
		}
	}
}

func (b *Bouncer) applyNew(decisions []*models.Decision) {
	for _, d := range decisions {
		if d.Value == nil || d.Type == nil || d.Scope == nil {
			continue
		}
		dec := &restrict.CrowdSecDecision{Type: restrict.DecisionType(*d.Type)}
		value := *d.Value

		if strings.ToLower(*d.Scope) == "range" || strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				b.logger.Debugf("skip unparsable CrowdSec range %q: %v", value, err)
				continue
			}
			prefix = normalizePrefix(prefix)
			b.prefixes[prefix] = dec
		} else {
			addr, err := netip.ParseAddr(value)
			if err != nil {
				b.logger.Debugf("skip unparsable CrowdSec IP %q: %v", value, err)
				continue
			}
			b.ips[addr.Unmap()] = dec
		}
	}
}

// normalizePrefix unmaps v4-mapped-v6 addresses and zeros host bits so
// the prefix is a valid map key that matches CheckIP's probe logic.
func normalizePrefix(p netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
}
