package relay

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v3"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/stdnet"
	nbnet "github.com/netbirdio/netbird/client/net"
)

const (
	DefaultCacheTTL = 20 * time.Second
)

var (
	ErrCheckInProgress = errors.New("probe check is already in progress")
)

// ProbeResult holds the info about the result of a relay probe request
type ProbeResult struct {
	URI  string
	Err  error
	Addr string
}

type StunTurnProbe struct {
	cacheResults    []ProbeResult
	cacheTimestamp  time.Time
	cacheKey        string
	cacheTTL        time.Duration
	probeInProgress bool
	mu              sync.Mutex
}

func NewStunTurnProb(cacheTTL time.Duration) *StunTurnProbe {
	return &StunTurnProbe{
		cacheTTL: cacheTTL,
	}
}

// ProbeAll probes all given servers asynchronously and returns the results
func (p *StunTurnProbe) ProbeAll(ctx context.Context, stuns []*stun.URI, turns []*stun.URI) []ProbeResult {
	cacheKey := generateCacheKey(stuns, turns)

	// Check cache first
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cacheKey == cacheKey && len(p.cacheResults) > 0 {
		age := time.Since(p.cacheTimestamp)
		if age < p.cacheTTL {
			results := append([]ProbeResult(nil), p.cacheResults...)
			log.Debugf("Returning cached probe results (age: %v)", age)
			return results
		}
	}

	if p.probeInProgress {
		return createErrorResults(stuns, turns)
	}

	p.probeInProgress = true
	go p.doProbe(ctx, stuns, turns, cacheKey)

	log.Infof("started new probe for STUN, TURN servers")
	return createErrorResults(stuns, turns)
}

func (p *StunTurnProbe) doProbe(ctx context.Context, stuns []*stun.URI, turns []*stun.URI, cacheKey string) {
	defer func() {
		p.mu.Lock()
		p.probeInProgress = false
		p.mu.Unlock()
	}()
	results := make([]ProbeResult, len(stuns)+len(turns))

	var wg sync.WaitGroup
	for i, uri := range stuns {
		wg.Add(1)
		go func(idx int, stunURI *stun.URI) {
			defer wg.Done()

			probeCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()

			results[idx].URI = stunURI.String()
			results[idx].Addr, results[idx].Err = p.probeSTUN(probeCtx, stunURI)
		}(i, uri)
	}

	stunOffset := len(stuns)
	for i, uri := range turns {
		wg.Add(1)
		go func(idx int, turnURI *stun.URI) {
			defer wg.Done()

			probeCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()

			results[idx].URI = turnURI.String()
			results[idx].Addr, results[idx].Err = p.probeTURN(probeCtx, turnURI)
		}(stunOffset+i, uri)
	}

	wg.Wait()

	// Store results in cache
	p.mu.Lock()
	p.cacheResults = results
	p.cacheTimestamp = time.Now()
	p.cacheKey = cacheKey
	p.mu.Unlock()

	log.Debug("Stored new probe results in cache")
}

// ProbeSTUN tries binding to the given STUN uri and acquiring an address
func (p *StunTurnProbe) probeSTUN(ctx context.Context, uri *stun.URI) (addr string, probeErr error) {
	defer func() {
		if probeErr != nil {
			log.Debugf("stun probe error from %s: %s", uri, probeErr)
		}
	}()

	net, err := stdnet.NewNet(nil)
	if err != nil {
		probeErr = fmt.Errorf("new net: %w", err)
		return
	}

	client, err := stun.DialURI(uri, &stun.DialConfig{
		Net: net,
	})
	if err != nil {
		probeErr = fmt.Errorf("dial: %w", err)
		return
	}

	defer func() {
		if err := client.Close(); err != nil && probeErr == nil {
			probeErr = fmt.Errorf("close: %w", err)
		}
	}()

	done := make(chan struct{})
	if err = client.Start(stun.MustBuild(stun.TransactionID, stun.BindingRequest), func(res stun.Event) {
		if res.Error != nil {
			probeErr = fmt.Errorf("request: %w", err)
			return
		}

		var xorAddr stun.XORMappedAddress
		if getErr := xorAddr.GetFrom(res.Message); getErr != nil {
			probeErr = fmt.Errorf("get xor addr: %w", err)
			return
		}

		log.Debugf("stun probe received address from %s: %s", uri, xorAddr)
		addr = xorAddr.String()

		done <- struct{}{}
	}); err != nil {
		probeErr = fmt.Errorf("client: %w", err)
		return
	}

	select {
	case <-ctx.Done():
		probeErr = fmt.Errorf("stun request: %w", ctx.Err())
		return
	case <-done:
	}

	return addr, nil
}

// ProbeTURN tries allocating a session from the given TURN URI
func (p *StunTurnProbe) probeTURN(ctx context.Context, uri *stun.URI) (addr string, probeErr error) {
	defer func() {
		if probeErr != nil {
			log.Debugf("turn probe error from %s: %s", uri, probeErr)
		}
	}()

	turnServerAddr := fmt.Sprintf("%s:%d", uri.Host, uri.Port)

	var conn net.PacketConn
	switch uri.Proto {
	case stun.ProtoTypeUDP:
		var err error
		conn, err = nbnet.NewListener().ListenPacket(ctx, "udp", "")
		if err != nil {
			probeErr = fmt.Errorf("listen: %w", err)
			return
		}
	case stun.ProtoTypeTCP:
		tcpConn, err := nbnet.NewDialer().DialContext(ctx, "tcp", turnServerAddr)
		if err != nil {
			probeErr = fmt.Errorf("dial: %w", err)
			return
		}
		conn = turn.NewSTUNConn(tcpConn)
	default:
		probeErr = fmt.Errorf("conn: unknown proto: %s", uri.Proto)
		return
	}

	defer func() {
		if err := conn.Close(); err != nil && probeErr == nil {
			probeErr = fmt.Errorf("conn close: %w", err)
		}
	}()

	net, err := stdnet.NewNet(nil)
	if err != nil {
		probeErr = fmt.Errorf("new net: %w", err)
		return
	}
	cfg := &turn.ClientConfig{
		STUNServerAddr: turnServerAddr,
		TURNServerAddr: turnServerAddr,
		Conn:           conn,
		Username:       uri.Username,
		Password:       uri.Password,
		Net:            net,
	}
	client, err := turn.NewClient(cfg)
	if err != nil {
		probeErr = fmt.Errorf("create client: %w", err)
		return
	}
	defer client.Close()

	if err := client.Listen(); err != nil {
		probeErr = fmt.Errorf("client listen: %w", err)
		return
	}

	relayConn, err := client.Allocate()
	if err != nil {
		probeErr = fmt.Errorf("allocate: %w", err)
		return
	}
	defer func() {
		if err := relayConn.Close(); err != nil && probeErr == nil {
			probeErr = fmt.Errorf("close relay conn: %w", err)
		}
	}()

	log.Debugf("turn probe relay address from %s: %s", uri, relayConn.LocalAddr())

	return relayConn.LocalAddr().String(), nil
}

func createErrorResults(stuns []*stun.URI, turns []*stun.URI) []ProbeResult {
	results := make([]ProbeResult, len(stuns)+len(turns))

	for i, uri := range stuns {
		results[i] = ProbeResult{
			URI: uri.String(),
			Err: ErrCheckInProgress,
		}
	}

	stunOffset := len(stuns)
	for i, uri := range turns {
		results[stunOffset+i] = ProbeResult{
			URI: uri.String(),
			Err: ErrCheckInProgress,
		}
	}

	return results
}

// generateCacheKey creates a unique key based on the URIs being probed
func generateCacheKey(stuns []*stun.URI, turns []*stun.URI) string {
	h := sha256.New()
	for _, uri := range stuns {
		h.Write([]byte(uri.String()))
	}
	for _, uri := range turns {
		h.Write([]byte(uri.String()))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
