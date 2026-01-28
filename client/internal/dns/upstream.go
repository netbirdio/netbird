package dns

import (
	"context"
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
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/dns/resutil"
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

type upstreamFailure struct {
	upstream netip.AddrPort
	reason   string
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
	logger := log.WithFields(log.Fields{
		"request_id": resutil.GetRequestID(w),
		"dns_id":     fmt.Sprintf("%04x", r.Id),
	})

	u.prepareRequest(r)

	if u.ctx.Err() != nil {
		logger.Tracef("%s has been stopped", u)
		return
	}

	ok, failures := u.tryUpstreamServers(w, r, logger)
	if len(failures) > 0 {
		u.logUpstreamFailures(r.Question[0].Name, failures, ok, logger)
	}
	if !ok {
		u.writeErrorResponse(w, r, logger)
	}
}

func (u *upstreamResolverBase) prepareRequest(r *dns.Msg) {
	if r.Extra == nil {
		r.MsgHdr.AuthenticatedData = true
	}
}

func (u *upstreamResolverBase) tryUpstreamServers(w dns.ResponseWriter, r *dns.Msg, logger *log.Entry) (bool, []upstreamFailure) {
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

	var failures []upstreamFailure
	for _, upstream := range u.upstreamServers {
		if failure := u.queryUpstream(w, r, upstream, timeout, logger); failure != nil {
			failures = append(failures, *failure)
		} else {
			return true, failures
		}
	}
	return false, failures
}

// queryUpstream queries a single upstream server. Returns nil on success, or failure info to try next upstream.
func (u *upstreamResolverBase) queryUpstream(w dns.ResponseWriter, r *dns.Msg, upstream netip.AddrPort, timeout time.Duration, logger *log.Entry) *upstreamFailure {
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
		return u.handleUpstreamError(err, upstream, startTime)
	}

	if rm == nil || !rm.Response {
		return &upstreamFailure{upstream: upstream, reason: "no response"}
	}

	if rm.Rcode == dns.RcodeServerFailure || rm.Rcode == dns.RcodeRefused {
		return &upstreamFailure{upstream: upstream, reason: dns.RcodeToString[rm.Rcode]}
	}

	u.writeSuccessResponse(w, rm, upstream, r.Question[0].Name, t, logger)
	return nil
}

func (u *upstreamResolverBase) handleUpstreamError(err error, upstream netip.AddrPort, startTime time.Time) *upstreamFailure {
	if !errors.Is(err, context.DeadlineExceeded) && !isTimeout(err) {
		return &upstreamFailure{upstream: upstream, reason: err.Error()}
	}

	elapsed := time.Since(startTime)
	reason := fmt.Sprintf("timeout after %v", elapsed.Truncate(time.Millisecond))
	if peerInfo := u.debugUpstreamTimeout(upstream); peerInfo != "" {
		reason += " " + peerInfo
	}
	return &upstreamFailure{upstream: upstream, reason: reason}
}

func (u *upstreamResolverBase) writeSuccessResponse(w dns.ResponseWriter, rm *dns.Msg, upstream netip.AddrPort, domain string, t time.Duration, logger *log.Entry) bool {
	u.successCount.Add(1)

	resutil.SetMeta(w, "upstream", upstream.String())

	// Clear Zero bit from external responses to prevent upstream servers from
	// manipulating our internal fallthrough signaling mechanism
	rm.MsgHdr.Zero = false

	if err := w.WriteMsg(rm); err != nil {
		logger.Errorf("failed to write DNS response for question domain=%s: %s", domain, err)
		return true
	}

	return true
}

func (u *upstreamResolverBase) logUpstreamFailures(domain string, failures []upstreamFailure, succeeded bool, logger *log.Entry) {
	totalUpstreams := len(u.upstreamServers)
	failedCount := len(failures)
	failureSummary := formatFailures(failures)

	if succeeded {
		logger.Warnf("%d/%d upstreams failed for domain=%s: %s", failedCount, totalUpstreams, domain, failureSummary)
	} else {
		logger.Errorf("%d/%d upstreams failed for domain=%s: %s", failedCount, totalUpstreams, domain, failureSummary)
	}
}

func (u *upstreamResolverBase) writeErrorResponse(w dns.ResponseWriter, r *dns.Msg, logger *log.Entry) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	if err := w.WriteMsg(m); err != nil {
		logger.Errorf("write error response for domain=%s: %s", r.Question[0].Name, err)
	}
}

func formatFailures(failures []upstreamFailure) string {
	parts := make([]string, 0, len(failures))
	for _, f := range failures {
		parts = append(parts, fmt.Sprintf("%s=%s", f.upstream, f.reason))
	}
	return strings.Join(parts, ", ")
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

// ExchangeWithNetstack performs a DNS exchange using netstack for dialing.
// This is needed when netstack is enabled to reach peer IPs through the tunnel.
func ExchangeWithNetstack(ctx context.Context, nsNet *netstack.Net, r *dns.Msg, upstream string) (*dns.Msg, error) {
	reply, err := netstackExchange(ctx, nsNet, r, upstream, "udp")
	if err != nil {
		return nil, err
	}

	// If response is truncated, retry with TCP
	if reply != nil && reply.MsgHdr.Truncated {
		log.Tracef("udp response for domain=%s type=%v class=%v is truncated, trying TCP",
			r.Question[0].Name, r.Question[0].Qtype, r.Question[0].Qclass)
		return netstackExchange(ctx, nsNet, r, upstream, "tcp")
	}

	return reply, nil
}

func netstackExchange(ctx context.Context, nsNet *netstack.Net, r *dns.Msg, upstream, network string) (*dns.Msg, error) {
	conn, err := nsNet.DialContext(ctx, network, upstream)
	if err != nil {
		return nil, fmt.Errorf("with %s: %w", network, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debugf("failed to close DNS connection: %v", err)
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	dnsConn := &dns.Conn{Conn: conn}

	if err := dnsConn.WriteMsg(r); err != nil {
		return nil, fmt.Errorf("write %s message: %w", network, err)
	}

	reply, err := dnsConn.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("read %s message: %w", network, err)
	}

	return reply, nil
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
