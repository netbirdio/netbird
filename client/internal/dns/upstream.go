package dns

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/dns/types"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
)

var currentMTU uint16 = iface.DefaultMTU

func SetCurrentMTU(mtu uint16) {
	currentMTU = mtu
}

const (
	UpstreamTimeout = 4 * time.Second
	// ClientTimeout is the timeout for the dns.Client.
	// Set longer than UpstreamTimeout to ensure context timeout takes precedence
	ClientTimeout = 5 * time.Second

	reactivatePeriod = 30 * time.Second
	probeTimeout     = 2 * time.Second
)

const testRecord = "com."

type upstreamClient interface {
	exchange(ctx context.Context, upstream string, r *dns.Msg) (*dns.Msg, time.Duration, error)
}

type UpstreamResolver interface {
	serveDNS(r *dns.Msg) (*dns.Msg, time.Duration, error)
	upstreamExchange(upstream string, r *dns.Msg) (*dns.Msg, time.Duration, error)
}

type upstreamResolverBase struct {
	ctx              context.Context
	cancel           context.CancelFunc
	upstreamClient   upstreamClient
	upstreamServers  []netip.AddrPort
	domain           string
	disabled         bool
	successCount     atomic.Int32
	mutex            sync.Mutex
	reactivatePeriod time.Duration
	upstreamTimeout  time.Duration

	deactivate     func(error)
	reactivate     func()
	statusRecorder *peer.Status
}

func newUpstreamResolverBase(ctx context.Context, statusRecorder *peer.Status, domain string) *upstreamResolverBase {
	ctx, cancel := context.WithCancel(ctx)

	return &upstreamResolverBase{
		ctx:              ctx,
		cancel:           cancel,
		domain:           domain,
		upstreamTimeout:  UpstreamTimeout,
		reactivatePeriod: reactivatePeriod,
		statusRecorder:   statusRecorder,
	}
}

// String returns a string representation of the upstream resolver
func (u *upstreamResolverBase) String() string {
	return fmt.Sprintf("Upstream %s", u.upstreamServers)
}

// ID returns the unique handler ID
func (u *upstreamResolverBase) ID() types.HandlerID {
	servers := slices.Clone(u.upstreamServers)
	slices.SortFunc(servers, func(a, b netip.AddrPort) int { return a.Compare(b) })

	hash := sha256.New()
	hash.Write([]byte(u.domain + ":"))
	for _, s := range servers {
		hash.Write([]byte(s.String()))
		hash.Write([]byte("|"))
	}
	return types.HandlerID("upstream-" + hex.EncodeToString(hash.Sum(nil)[:8]))
}

func (u *upstreamResolverBase) MatchSubdomains() bool {
	return true
}

func (u *upstreamResolverBase) Stop() {
	log.Debugf("stopping serving DNS for upstreams %s", u.upstreamServers)
	u.cancel()
}

// ServeDNS handles a DNS request
func (u *upstreamResolverBase) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	requestID := GenerateRequestID()
	logger := log.WithField("request_id", requestID)

	logger.Tracef("received upstream question: domain=%s type=%v class=%v", r.Question[0].Name, r.Question[0].Qtype, r.Question[0].Qclass)

	u.prepareRequest(r)

	if u.ctx.Err() != nil {
		logger.Tracef("%s has been stopped", u)
		return
	}

	if u.tryUpstreamServers(w, r, logger) {
		return
	}

	u.writeErrorResponse(w, r, logger)
}

func (u *upstreamResolverBase) prepareRequest(r *dns.Msg) {
	if r.Extra == nil {
		r.MsgHdr.AuthenticatedData = true
	}
}

func (u *upstreamResolverBase) tryUpstreamServers(w dns.ResponseWriter, r *dns.Msg, logger *log.Entry) bool {
	timeout := u.upstreamTimeout
	if len(u.upstreamServers) > 1 {
		maxTotal := 5 * time.Second
		minPerUpstream := 2 * time.Second
		scaledTimeout := maxTotal / time.Duration(len(u.upstreamServers))
		if scaledTimeout > minPerUpstream {
			timeout = scaledTimeout
		} else {
			timeout = minPerUpstream
		}
	}

	for _, upstream := range u.upstreamServers {
		if u.queryUpstream(w, r, upstream, timeout, logger) {
			return true
		}
	}
	return false
}

func (u *upstreamResolverBase) queryUpstream(w dns.ResponseWriter, r *dns.Msg, upstream netip.AddrPort, timeout time.Duration, logger *log.Entry) bool {
	var rm *dns.Msg
	var t time.Duration
	var err error

	var startTime time.Time
	func() {
		ctx, cancel := context.WithTimeout(u.ctx, timeout)
		defer cancel()
		startTime = time.Now()
		rm, t, err = u.upstreamClient.exchange(ctx, upstream.String(), r)
	}()

	if err != nil {
		u.handleUpstreamError(err, upstream, r.Question[0].Name, startTime, timeout, logger)
		return false
	}

	if rm == nil || !rm.Response {
		logger.Warnf("no response from upstream %s for question domain=%s", upstream, r.Question[0].Name)
		return false
	}

	return u.writeSuccessResponse(w, rm, upstream, r.Question[0].Name, t, logger)
}

func (u *upstreamResolverBase) handleUpstreamError(err error, upstream netip.AddrPort, domain string, startTime time.Time, timeout time.Duration, logger *log.Entry) {
	if !errors.Is(err, context.DeadlineExceeded) && !isTimeout(err) {
		logger.Warnf("failed to query upstream %s for question domain=%s: %s", upstream, domain, err)
		return
	}

	elapsed := time.Since(startTime)
	timeoutMsg := fmt.Sprintf("upstream %s timed out for question domain=%s after %v (timeout=%v)", upstream, domain, elapsed.Truncate(time.Millisecond), timeout)
	if peerInfo := u.debugUpstreamTimeout(upstream); peerInfo != "" {
		timeoutMsg += " " + peerInfo
	}
	timeoutMsg += fmt.Sprintf(" - error: %v", err)
	logger.Warn(timeoutMsg)
}

func (u *upstreamResolverBase) writeSuccessResponse(w dns.ResponseWriter, rm *dns.Msg, upstream netip.AddrPort, domain string, t time.Duration, logger *log.Entry) bool {
	u.successCount.Add(1)
	logger.Tracef("took %s to query the upstream %s for question domain=%s", t, upstream, domain)

	if err := w.WriteMsg(rm); err != nil {
		logger.Errorf("failed to write DNS response for question domain=%s: %s", domain, err)
	}
	return true
}

func (u *upstreamResolverBase) writeErrorResponse(w dns.ResponseWriter, r *dns.Msg, logger *log.Entry) {
	logger.Errorf("all queries to the %s failed for question domain=%s", u, r.Question[0].Name)

	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	if err := w.WriteMsg(m); err != nil {
		logger.Errorf("failed to write error response for %s for question domain=%s: %s", u, r.Question[0].Name, err)
	}
}

// ProbeAvailability tests all upstream servers simultaneously and
// disables the resolver if none work
func (u *upstreamResolverBase) ProbeAvailability() {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	select {
	case <-u.ctx.Done():
		return
	default:
	}

	// avoid probe if upstreams could resolve at least one query
	if u.successCount.Load() > 0 {
		return
	}

	var success bool
	var mu sync.Mutex
	var wg sync.WaitGroup

	var errors *multierror.Error
	for _, upstream := range u.upstreamServers {
		upstream := upstream

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := u.testNameserver(upstream, 500*time.Millisecond)
			if err != nil {
				errors = multierror.Append(errors, err)
				log.Warnf("probing upstream nameserver %s: %s", upstream, err)
				return
			}

			mu.Lock()
			defer mu.Unlock()
			success = true
		}()
	}

	wg.Wait()

	// didn't find a working upstream server, let's disable and try later
	if !success {
		u.disable(errors.ErrorOrNil())

		if u.statusRecorder == nil {
			return
		}

		u.statusRecorder.PublishEvent(
			proto.SystemEvent_WARNING,
			proto.SystemEvent_DNS,
			"All upstream servers failed (probe failed)",
			"Unable to reach one or more DNS servers. This might affect your ability to connect to some services.",
			map[string]string{"upstreams": u.upstreamServersString()},
		)
	}
}

// waitUntilResponse retries, in an exponential interval, querying the upstream servers until it gets a positive response
func (u *upstreamResolverBase) waitUntilResponse() {
	exponentialBackOff := &backoff.ExponentialBackOff{
		InitialInterval:     500 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.1,
		MaxInterval:         u.reactivatePeriod,
		MaxElapsedTime:      0,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}

	operation := func() error {
		select {
		case <-u.ctx.Done():
			return backoff.Permanent(fmt.Errorf("exiting upstream retry loop for upstreams %s: parent context has been canceled", u.upstreamServersString()))
		default:
		}

		for _, upstream := range u.upstreamServers {
			if err := u.testNameserver(upstream, probeTimeout); err != nil {
				log.Tracef("upstream check for %s: %s", upstream, err)
			} else {
				// at least one upstream server is available, stop probing
				return nil
			}
		}

		log.Tracef("checking connectivity with upstreams %s failed. Retrying in %s", u.upstreamServersString(), exponentialBackOff.NextBackOff())
		return fmt.Errorf("upstream check call error")
	}

	err := backoff.Retry(operation, exponentialBackOff)
	if err != nil {
		log.Warn(err)
		return
	}

	log.Infof("upstreams %s are responsive again. Adding them back to system", u.upstreamServersString())
	u.successCount.Add(1)
	u.reactivate()
	u.disabled = false
}

// isTimeout returns true if the given error is a network timeout error.
//
// Copied from k8s.io/apimachinery/pkg/util/net.IsTimeout
func isTimeout(err error) bool {
	var neterr net.Error
	if errors.As(err, &neterr) {
		return neterr != nil && neterr.Timeout()
	}
	return false
}

func (u *upstreamResolverBase) disable(err error) {
	if u.disabled {
		return
	}

	log.Warnf("Upstream resolving is Disabled for %v", reactivatePeriod)
	u.successCount.Store(0)
	u.deactivate(err)
	u.disabled = true
	go u.waitUntilResponse()
}

func (u *upstreamResolverBase) upstreamServersString() string {
	var servers []string
	for _, server := range u.upstreamServers {
		servers = append(servers, server.String())
	}
	return strings.Join(servers, ", ")
}

func (u *upstreamResolverBase) testNameserver(server netip.AddrPort, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(u.ctx, timeout)
	defer cancel()

	r := new(dns.Msg).SetQuestion(testRecord, dns.TypeSOA)

	_, _, err := u.upstreamClient.exchange(ctx, server.String(), r)
	return err
}

// ExchangeWithFallback exchanges a DNS message with the upstream server.
// It first tries to use UDP, and if it is truncated, it falls back to TCP.
// If the passed context is nil, this will use Exchange instead of ExchangeContext.
func ExchangeWithFallback(ctx context.Context, client *dns.Client, r *dns.Msg, upstream string) (*dns.Msg, time.Duration, error) {
	// MTU - ip + udp headers
	// Note: this could be sent out on an interface that is not ours, but higher MTU settings could break truncation handling.
	client.UDPSize = uint16(currentMTU - (60 + 8))

	var (
		rm  *dns.Msg
		t   time.Duration
		err error
	)

	if ctx == nil {
		rm, t, err = client.Exchange(r, upstream)
	} else {
		rm, t, err = client.ExchangeContext(ctx, r, upstream)
	}

	if err != nil {
		return nil, t, fmt.Errorf("with udp: %w", err)
	}

	if rm == nil || !rm.MsgHdr.Truncated {
		return rm, t, nil
	}

	log.Tracef("udp response for domain=%s type=%v class=%v is truncated, trying TCP.",
		r.Question[0].Name, r.Question[0].Qtype, r.Question[0].Qclass)

	client.Net = "tcp"

	if ctx == nil {
		rm, t, err = client.Exchange(r, upstream)
	} else {
		rm, t, err = client.ExchangeContext(ctx, r, upstream)
	}

	if err != nil {
		return nil, t, fmt.Errorf("with tcp: %w", err)
	}

	// TODO: once TCP is implemented, rm.Truncate() if the request came in over UDP

	return rm, t, nil
}

func GenerateRequestID() string {
	bytes := make([]byte, 4)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Errorf("failed to generate request ID: %v", err)
		return ""
	}
	return hex.EncodeToString(bytes)
}

// FormatPeerStatus formats peer connection status information for debugging DNS timeouts
func FormatPeerStatus(peerState *peer.State) string {
	isConnected := peerState.ConnStatus == peer.StatusConnected
	hasRecentHandshake := !peerState.LastWireguardHandshake.IsZero() &&
		time.Since(peerState.LastWireguardHandshake) < 3*time.Minute

	statusInfo := fmt.Sprintf("%s:%s", peerState.FQDN, peerState.IP)

	switch {
	case !isConnected:
		statusInfo += " DISCONNECTED"
	case !hasRecentHandshake:
		statusInfo += " NO_RECENT_HANDSHAKE"
	default:
		statusInfo += " connected"
	}

	if !peerState.LastWireguardHandshake.IsZero() {
		timeSinceHandshake := time.Since(peerState.LastWireguardHandshake)
		statusInfo += fmt.Sprintf(" last_handshake=%v_ago", timeSinceHandshake.Truncate(time.Second))
	} else {
		statusInfo += " no_handshake"
	}

	if peerState.Relayed {
		statusInfo += " via_relay"
	}

	if peerState.Latency > 0 {
		statusInfo += fmt.Sprintf(" latency=%v", peerState.Latency)
	}

	return statusInfo
}

// findPeerForIP finds which peer handles the given IP address
func findPeerForIP(ip netip.Addr, statusRecorder *peer.Status) *peer.State {
	if statusRecorder == nil {
		return nil
	}

	fullStatus := statusRecorder.GetFullStatus()
	var bestMatch *peer.State
	var bestPrefixLen int

	for _, peerState := range fullStatus.Peers {
		routes := peerState.GetRoutes()
		for route := range routes {
			prefix, err := netip.ParsePrefix(route)
			if err != nil {
				continue
			}

			if prefix.Contains(ip) && prefix.Bits() > bestPrefixLen {
				peerStateCopy := peerState
				bestMatch = &peerStateCopy
				bestPrefixLen = prefix.Bits()
			}
		}
	}

	return bestMatch
}

func (u *upstreamResolverBase) debugUpstreamTimeout(upstream netip.AddrPort) string {
	if u.statusRecorder == nil {
		return ""
	}

	peerInfo := findPeerForIP(upstream.Addr(), u.statusRecorder)
	if peerInfo == nil {
		return ""
	}

	return fmt.Sprintf("(routes through NetBird peer %s)", FormatPeerStatus(peerInfo))
}
