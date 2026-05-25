// Package dns implements the client-side DNS stack: listener/service on the
// peer's tunnel address, handler chain that routes questions by domain and
// priority, and upstream resolvers that forward what remains to configured
// nameservers.
//
// # Upstream resolution and the race model
//
// When two or more nameserver groups target the same domain, DefaultServer
// merges them into one upstream handler whose state is:
//
//	upstreamResolverBase
//	  └── upstreamServers []upstreamRace   // one entry per source NS group
//	        └── []netip.AddrPort           // primary, fallback, ...
//
// Each source nameserver group contributes one upstreamRace. Within a race
// upstreams are tried in order: the next is used only on failure (timeout,
// SERVFAIL, REFUSED, no response). NXDOMAIN is a valid answer and stops
// the walk. When more than one race exists, ServeDNS fans out one
// goroutine per race and returns the first valid answer, cancelling the
// rest. A handler with a single race skips the fan-out.
//
// # Health projection
//
// Query outcomes are recorded per-upstream in UpstreamHealth. The server
// periodically merges these snapshots across handlers and projects them
// into peer.NSGroupState. There is no active probing: a group is marked
// unhealthy only when every seen upstream has a recent failure and none
// has a recent success. Healthy→unhealthy fires a single
// SystemEvent_WARNING; steady-state refreshes do not duplicate it.
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
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/dns/resutil"
	"github.com/netbirdio/netbird/client/internal/dns/types"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

var currentMTU uint16 = iface.DefaultMTU

// nonRetryableEDECodes lists EDE info codes (RFC 8914) for which a SERVFAIL
// from one upstream means another upstream would return the same answer:
// DNSSEC validation outcomes and policy-based blocks. Transient errors
// (network, cached, not ready) are not included.
var nonRetryableEDECodes = map[uint16]struct{}{
	dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm: {},
	dns.ExtendedErrorCodeUnsupportedDSDigestType:    {},
	dns.ExtendedErrorCodeDNSSECIndeterminate:        {},
	dns.ExtendedErrorCodeDNSBogus:                   {},
	dns.ExtendedErrorCodeSignatureExpired:           {},
	dns.ExtendedErrorCodeSignatureNotYetValid:       {},
	dns.ExtendedErrorCodeDNSKEYMissing:              {},
	dns.ExtendedErrorCodeRRSIGsMissing:              {},
	dns.ExtendedErrorCodeNoZoneKeyBitSet:            {},
	dns.ExtendedErrorCodeNSECMissing:                {},
	dns.ExtendedErrorCodeBlocked:                    {},
	dns.ExtendedErrorCodeCensored:                   {},
	dns.ExtendedErrorCodeFiltered:                   {},
	dns.ExtendedErrorCodeProhibited:                 {},
}

// privateClientIface is the subset of the WireGuard interface needed by GetClientPrivate.
type privateClientIface interface {
	Name() string
	Address() wgaddr.Address
}

func SetCurrentMTU(mtu uint16) {
	currentMTU = mtu
}

const (
	UpstreamTimeout = 4 * time.Second
	// ClientTimeout is the timeout for the dns.Client.
	// Set longer than UpstreamTimeout to ensure context timeout takes precedence
	ClientTimeout = 5 * time.Second

	// ipv6HeaderSize + udpHeaderSize, used to derive the maximum DNS UDP
	// payload from the tunnel MTU.
	ipUDPHeaderSize = 60 + 8

	// raceMaxTotalTimeout caps the combined time spent walking all upstreams
	// within one race, so a slow primary can't eat the whole race budget.
	raceMaxTotalTimeout = 5 * time.Second
	// raceMinPerUpstreamTimeout is the floor applied when dividing
	// raceMaxTotalTimeout across upstreams within a race.
	raceMinPerUpstreamTimeout = 2 * time.Second
)

const (
	protoUDP = "udp"
	protoTCP = "tcp"
)

type dnsProtocolKey struct{}

type upstreamProtocolKey struct{}

// upstreamProtocolResult holds the protocol used for the upstream exchange.
// Stored as a pointer in context so the exchange function can set it.
type upstreamProtocolResult struct {
	protocol string
}

type upstreamClient interface {
	exchange(ctx context.Context, upstream string, r *dns.Msg) (*dns.Msg, time.Duration, error)
}

type UpstreamResolver interface {
	serveDNS(r *dns.Msg) (*dns.Msg, time.Duration, error)
	upstreamExchange(upstream string, r *dns.Msg) (*dns.Msg, time.Duration, error)
}

// upstreamRace is an ordered list of upstreams derived from one configured
// nameserver group. Order matters: the first upstream is tried first, the
// second only on failure, and so on. Multiple upstreamRace values coexist
// inside one resolver when overlapping nameserver groups target the same
// domain; those races run in parallel and the first valid answer wins.
type upstreamRace []netip.AddrPort

// UpstreamHealth is the last query-path outcome for a single upstream,
// consumed by nameserver-group status projection.
type UpstreamHealth struct {
	LastOk   time.Time
	LastFail time.Time
	LastErr  string
}

type upstreamResolverBase struct {
	ctx             context.Context
	cancel          context.CancelFunc
	upstreamClient  upstreamClient
	upstreamServers []upstreamRace
	domain          domain.Domain
	upstreamTimeout time.Duration

	healthMu sync.RWMutex
	health   map[netip.AddrPort]*UpstreamHealth

	statusRecorder *peer.Status
	// selectedRoutes returns the current set of client routes the admin
	// has enabled. Called lazily from the query hot path when an upstream
	// might need a tunnel-bound client (iOS) and from health projection.
	selectedRoutes func() route.HAMap
}

type upstreamFailure struct {
	upstream netip.AddrPort
	reason   string
}

type raceResult struct {
	msg      *dns.Msg
	upstream netip.AddrPort
	protocol string
	ede      string
	failures []upstreamFailure
}

// contextWithDNSProtocol stores the inbound DNS protocol ("udp" or "tcp") in context.
func contextWithDNSProtocol(ctx context.Context, network string) context.Context {
	return context.WithValue(ctx, dnsProtocolKey{}, network)
}

// dnsProtocolFromContext retrieves the inbound DNS protocol from context.
func dnsProtocolFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(dnsProtocolKey{}).(string); ok {
		return v
	}
	return ""
}

// contextWithUpstreamProtocolResult stores a mutable result holder in the context.
func contextWithUpstreamProtocolResult(ctx context.Context) (context.Context, *upstreamProtocolResult) {
	r := &upstreamProtocolResult{}
	return context.WithValue(ctx, upstreamProtocolKey{}, r), r
}

// setUpstreamProtocol sets the upstream protocol on the result holder in context, if present.
func setUpstreamProtocol(ctx context.Context, protocol string) {
	if ctx == nil {
		return
	}
	if r, ok := ctx.Value(upstreamProtocolKey{}).(*upstreamProtocolResult); ok && r != nil {
		r.protocol = protocol
	}
}

func newUpstreamResolverBase(ctx context.Context, statusRecorder *peer.Status, d domain.Domain) *upstreamResolverBase {
	ctx, cancel := context.WithCancel(ctx)

	return &upstreamResolverBase{
		ctx:             ctx,
		cancel:          cancel,
		domain:          d,
		upstreamTimeout: UpstreamTimeout,
		statusRecorder:  statusRecorder,
	}
}

// String returns a string representation of the upstream resolver
func (u *upstreamResolverBase) String() string {
	return fmt.Sprintf("Upstream %s", u.flatUpstreams())
}

// ID returns the unique handler ID. Race groupings and within-race
// ordering are both part of the identity: [[A,B]] and [[A],[B]] query
// the same servers but with different semantics (serial fallback vs
// parallel race), so their handlers must not collide.
func (u *upstreamResolverBase) ID() types.HandlerID {
	hash := sha256.New()
	hash.Write([]byte(u.domain.PunycodeString() + ":"))
	for _, race := range u.upstreamServers {
		hash.Write([]byte("["))
		for _, s := range race {
			hash.Write([]byte(s.String()))
			hash.Write([]byte("|"))
		}
		hash.Write([]byte("]"))
	}
	return types.HandlerID("upstream-" + hex.EncodeToString(hash.Sum(nil)[:8]))
}

func (u *upstreamResolverBase) MatchSubdomains() bool {
	return true
}

func (u *upstreamResolverBase) Stop() {
	log.Debugf("stopping serving DNS for upstreams %s", u.flatUpstreams())
	u.cancel()
}

// flatUpstreams is for logging and ID hashing only, not for dispatch.
func (u *upstreamResolverBase) flatUpstreams() []netip.AddrPort {
	var out []netip.AddrPort
	for _, g := range u.upstreamServers {
		out = append(out, g...)
	}
	return out
}

// setSelectedRoutes swaps the accessor used to classify overlay-routed
// upstreams. Called when route sources are wired after the handler was
// built (permanent / iOS constructors).
func (u *upstreamResolverBase) setSelectedRoutes(selected func() route.HAMap) {
	u.selectedRoutes = selected
}

func (u *upstreamResolverBase) addRace(servers []netip.AddrPort) {
	if len(servers) == 0 {
		return
	}
	u.upstreamServers = append(u.upstreamServers, slices.Clone(servers))
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

	// Propagate inbound protocol so upstream exchange can use TCP directly
	// when the request came in over TCP.
	ctx := u.ctx
	if addr := w.RemoteAddr(); addr != nil {
		network := addr.Network()
		ctx = contextWithDNSProtocol(ctx, network)
		resutil.SetMeta(w, "protocol", network)
	}

	ok, failures := u.tryUpstreamServers(ctx, w, r, logger)
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

func (u *upstreamResolverBase) tryUpstreamServers(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, logger *log.Entry) (bool, []upstreamFailure) {
	groups := u.upstreamServers
	switch len(groups) {
	case 0:
		return false, nil
	case 1:
		return u.tryOnlyRace(ctx, w, r, groups[0], logger)
	default:
		return u.raceAll(ctx, w, r, groups, logger)
	}
}

func (u *upstreamResolverBase) tryOnlyRace(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, group upstreamRace, logger *log.Entry) (bool, []upstreamFailure) {
	res := u.tryRace(ctx, r, group)
	if res.msg == nil {
		return false, res.failures
	}
	if res.ede != "" {
		resutil.SetMeta(w, "ede", res.ede)
	}
	u.writeSuccessResponse(w, res.msg, res.upstream, r.Question[0].Name, res.protocol, logger)
	return true, res.failures
}

// raceAll runs one worker per group in parallel, taking the first valid
// answer and cancelling the rest.
func (u *upstreamResolverBase) raceAll(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, groups []upstreamRace, logger *log.Entry) (bool, []upstreamFailure) {
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Buffer sized to len(groups) so workers never block on send, even
	// after the coordinator has returned.
	results := make(chan raceResult, len(groups))
	for _, g := range groups {
		// tryRace clones the request per attempt, so workers never share
		// a *dns.Msg and concurrent EDNS0 mutations can't race.
		go func(g upstreamRace) {
			results <- u.tryRace(raceCtx, r, g)
		}(g)
	}

	var failures []upstreamFailure
	for range groups {
		select {
		case res := <-results:
			failures = append(failures, res.failures...)
			if res.msg != nil {
				if res.ede != "" {
					resutil.SetMeta(w, "ede", res.ede)
				}
				u.writeSuccessResponse(w, res.msg, res.upstream, r.Question[0].Name, res.protocol, logger)
				return true, failures
			}
		case <-ctx.Done():
			return false, failures
		}
	}
	return false, failures
}

func (u *upstreamResolverBase) tryRace(ctx context.Context, r *dns.Msg, group upstreamRace) raceResult {
	timeout := u.upstreamTimeout
	if len(group) > 1 {
		// Cap the whole walk at raceMaxTotalTimeout: per-upstream timeouts
		// still honor raceMinPerUpstreamTimeout as a floor for correctness
		// on slow links, but the outer context ensures the combined walk
		// cannot exceed the cap regardless of group size.
		timeout = max(raceMaxTotalTimeout/time.Duration(len(group)), raceMinPerUpstreamTimeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, raceMaxTotalTimeout)
		defer cancel()
	}

	var failures []upstreamFailure
	for _, upstream := range group {
		if ctx.Err() != nil {
			return raceResult{failures: failures}
		}
		// Clone the request per attempt: the exchange path mutates EDNS0
		// options in-place, so reusing the same *dns.Msg across sequential
		// upstreams would carry those mutations (e.g. a reduced UDP size)
		// into the next attempt.
		res, failure := u.queryUpstream(ctx, r.Copy(), upstream, timeout)
		if failure != nil {
			failures = append(failures, *failure)
			continue
		}
		res.failures = failures
		return res
	}
	return raceResult{failures: failures}
}

func (u *upstreamResolverBase) queryUpstream(parentCtx context.Context, r *dns.Msg, upstream netip.AddrPort, timeout time.Duration) (raceResult, *upstreamFailure) {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	ctx, upstreamProto := contextWithUpstreamProtocolResult(ctx)

	// Advertise EDNS0 so the upstream may include Extended DNS Errors
	// (RFC 8914) in failure responses; we use those to short-circuit
	// failover for definitive answers like DNSSEC validation failures.
	// The caller already passed a per-attempt copy, so we can mutate r
	// directly; hadEdns reflects the original client request's state and
	// controls whether we strip the OPT from the response.
	hadEdns := r.IsEdns0() != nil
	if !hadEdns {
		r.SetEdns0(upstreamUDPSize(), false)
	}

	startTime := time.Now()
	rm, _, err := u.upstreamClient.exchange(ctx, upstream.String(), r)

	if err != nil {
		// A parent cancellation (e.g., another race won and the coordinator
		// cancelled the losers) is not an upstream failure. Check both the
		// error chain and the parent context: a transport may surface the
		// cancellation as a read/deadline error rather than context.Canceled.
		if errors.Is(err, context.Canceled) || errors.Is(parentCtx.Err(), context.Canceled) {
			return raceResult{}, &upstreamFailure{upstream: upstream, reason: "canceled"}
		}
		failure := u.handleUpstreamError(err, upstream, startTime)
		u.markUpstreamFail(upstream, failure.reason)
		return raceResult{}, failure
	}

	if rm == nil || !rm.Response {
		u.markUpstreamFail(upstream, "no response")
		return raceResult{}, &upstreamFailure{upstream: upstream, reason: "no response"}
	}

	proto := ""
	if upstreamProto != nil {
		proto = upstreamProto.protocol
	}

	if rm.Rcode == dns.RcodeServerFailure || rm.Rcode == dns.RcodeRefused {
		if code, ok := nonRetryableEDE(rm); ok {
			if !hadEdns {
				stripOPT(rm)
			}
			u.markUpstreamOk(upstream)
			return raceResult{msg: rm, upstream: upstream, protocol: proto, ede: edeName(code)}, nil
		}
		reason := dns.RcodeToString[rm.Rcode]
		u.markUpstreamFail(upstream, reason)
		return raceResult{}, &upstreamFailure{upstream: upstream, reason: reason}
	}

	if !hadEdns {
		stripOPT(rm)
	}

	u.markUpstreamOk(upstream)
	return raceResult{msg: rm, upstream: upstream, protocol: proto}, nil
}

// healthEntry returns the mutable health record for addr, lazily creating
// the map and the entry. Caller must hold u.healthMu.
func (u *upstreamResolverBase) healthEntry(addr netip.AddrPort) *UpstreamHealth {
	if u.health == nil {
		u.health = make(map[netip.AddrPort]*UpstreamHealth)
	}
	h := u.health[addr]
	if h == nil {
		h = &UpstreamHealth{}
		u.health[addr] = h
	}
	return h
}

func (u *upstreamResolverBase) markUpstreamOk(addr netip.AddrPort) {
	u.healthMu.Lock()
	defer u.healthMu.Unlock()
	h := u.healthEntry(addr)
	h.LastOk = time.Now()
	h.LastFail = time.Time{}
	h.LastErr = ""
}

func (u *upstreamResolverBase) markUpstreamFail(addr netip.AddrPort, reason string) {
	u.healthMu.Lock()
	defer u.healthMu.Unlock()
	h := u.healthEntry(addr)
	h.LastFail = time.Now()
	h.LastErr = reason
}

// UpstreamHealth returns a snapshot of per-upstream query outcomes.
func (u *upstreamResolverBase) UpstreamHealth() map[netip.AddrPort]UpstreamHealth {
	u.healthMu.RLock()
	defer u.healthMu.RUnlock()
	out := make(map[netip.AddrPort]UpstreamHealth, len(u.health))
	for k, v := range u.health {
		out[k] = *v
	}
	return out
}

// upstreamUDPSize returns the EDNS0 UDP buffer size we advertise to upstreams,
// derived from the tunnel MTU and bounded against underflow.
func upstreamUDPSize() uint16 {
	if currentMTU > ipUDPHeaderSize {
		return currentMTU - ipUDPHeaderSize
	}
	return dns.MinMsgSize
}

// stripOPT removes any OPT pseudo-RRs from the response's Extra section so
// the response complies with RFC 6891 when the client did not advertise EDNS0.
func stripOPT(rm *dns.Msg) {
	if len(rm.Extra) == 0 {
		return
	}
	out := rm.Extra[:0]
	for _, rr := range rm.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		out = append(out, rr)
	}
	rm.Extra = out
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

func (u *upstreamResolverBase) writeSuccessResponse(w dns.ResponseWriter, rm *dns.Msg, upstream netip.AddrPort, domain string, proto string, logger *log.Entry) {
	resutil.SetMeta(w, "upstream", upstream.String())
	if proto != "" {
		resutil.SetMeta(w, "upstream_protocol", proto)
	}

	// Clear Zero bit from external responses to prevent upstream servers from
	// manipulating our internal fallthrough signaling mechanism
	rm.MsgHdr.Zero = false

	if err := w.WriteMsg(rm); err != nil {
		logger.Errorf("failed to write DNS response for question domain=%s: %s", domain, err)
	}
}

func (u *upstreamResolverBase) logUpstreamFailures(domain string, failures []upstreamFailure, succeeded bool, logger *log.Entry) {
	totalUpstreams := len(u.flatUpstreams())
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

// nonRetryableEDE returns the first non-retryable EDE code carried in the
// response, if any.
func nonRetryableEDE(rm *dns.Msg) (uint16, bool) {
	opt := rm.IsEdns0()
	if opt == nil {
		return 0, false
	}
	for _, o := range opt.Option {
		ede, ok := o.(*dns.EDNS0_EDE)
		if !ok {
			continue
		}
		if _, ok := nonRetryableEDECodes[ede.InfoCode]; ok {
			return ede.InfoCode, true
		}
	}
	return 0, false
}

// edeName returns a human-readable name for an EDE code, falling back to
// the numeric code when unknown.
func edeName(code uint16) string {
	if name, ok := dns.ExtendedErrorCodeToString[code]; ok {
		return name
	}
	return fmt.Sprintf("EDE %d", code)
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

// clientUDPMaxSize returns the maximum UDP response size the client accepts.
func clientUDPMaxSize(r *dns.Msg) int {
	if opt := r.IsEdns0(); opt != nil {
		return int(opt.UDPSize())
	}
	return dns.MinMsgSize
}

// ExchangeWithFallback exchanges a DNS message with the upstream server.
// It first tries to use UDP, and if it is truncated, it falls back to TCP.
// If the inbound request came over TCP (via context), it skips the UDP attempt.
func ExchangeWithFallback(ctx context.Context, client *dns.Client, r *dns.Msg, upstream string) (*dns.Msg, time.Duration, error) {
	// If the request came in over TCP, go straight to TCP upstream.
	if dnsProtocolFromContext(ctx) == protoTCP {
		rm, t, err := toTCPClient(client).ExchangeContext(ctx, r, upstream)
		if err != nil {
			return nil, t, fmt.Errorf("with tcp: %w", err)
		}
		setUpstreamProtocol(ctx, protoTCP)
		return rm, t, nil
	}

	clientMaxSize := clientUDPMaxSize(r)

	// Cap EDNS0 to our tunnel MTU so the upstream doesn't send a
	// response larger than our read buffer.
	// Note: the query could be sent out on an interface that is not ours,
	// but higher MTU settings could break truncation handling.
	maxUDPPayload := uint16(currentMTU - ipUDPHeaderSize)
	client.UDPSize = maxUDPPayload
	if opt := r.IsEdns0(); opt != nil && opt.UDPSize() > maxUDPPayload {
		opt.SetUDPSize(maxUDPPayload)
	}

	rm, t, err := client.ExchangeContext(ctx, r, upstream)
	if err != nil {
		return nil, t, fmt.Errorf("with udp: %w", err)
	}

	if rm == nil || !rm.MsgHdr.Truncated {
		setUpstreamProtocol(ctx, protoUDP)
		return rm, t, nil
	}

	// TODO: if the upstream's truncated UDP response already contains more
	// data than the client's buffer, we could truncate locally and skip
	// the TCP retry.

	rm, t, err = toTCPClient(client).ExchangeContext(ctx, r, upstream)
	if err != nil {
		return nil, t, fmt.Errorf("with tcp: %w", err)
	}

	setUpstreamProtocol(ctx, protoTCP)

	if rm.Len() > clientMaxSize {
		rm.Truncate(clientMaxSize)
	}

	return rm, t, nil
}

// toTCPClient returns a copy of c configured for TCP. If c's Dialer has a
// *net.UDPAddr bound as LocalAddr (iOS does this to keep the source IP on
// the tunnel interface), it is converted to the equivalent *net.TCPAddr
// so net.Dialer doesn't reject the TCP dial with "mismatched local
// address type".
func toTCPClient(c *dns.Client) *dns.Client {
	tcp := *c
	tcp.Net = protoTCP
	if tcp.Dialer == nil {
		return &tcp
	}
	d := *tcp.Dialer
	if ua, ok := d.LocalAddr.(*net.UDPAddr); ok {
		d.LocalAddr = &net.TCPAddr{IP: ua.IP, Port: ua.Port, Zone: ua.Zone}
	}
	tcp.Dialer = &d
	return &tcp
}

// ExchangeWithNetstack performs a DNS exchange using netstack for dialing.
// This is needed when netstack is enabled to reach peer IPs through the tunnel.
func ExchangeWithNetstack(ctx context.Context, nsNet *netstack.Net, r *dns.Msg, upstream string) (*dns.Msg, error) {
	// If request came in over TCP, go straight to TCP upstream
	if dnsProtocolFromContext(ctx) == protoTCP {
		rm, err := netstackExchange(ctx, nsNet, r, upstream, protoTCP)
		if err != nil {
			return nil, err
		}
		setUpstreamProtocol(ctx, protoTCP)
		return rm, nil
	}

	clientMaxSize := clientUDPMaxSize(r)

	// Cap EDNS0 to our tunnel MTU so the upstream doesn't send a
	// response larger than what we can read over UDP.
	maxUDPPayload := uint16(currentMTU - ipUDPHeaderSize)
	if opt := r.IsEdns0(); opt != nil && opt.UDPSize() > maxUDPPayload {
		opt.SetUDPSize(maxUDPPayload)
	}

	reply, err := netstackExchange(ctx, nsNet, r, upstream, protoUDP)
	if err != nil {
		return nil, err
	}

	if reply != nil && reply.MsgHdr.Truncated {
		rm, err := netstackExchange(ctx, nsNet, r, upstream, protoTCP)
		if err != nil {
			return nil, err
		}

		setUpstreamProtocol(ctx, protoTCP)
		if rm.Len() > clientMaxSize {
			rm.Truncate(clientMaxSize)
		}

		return rm, nil
	}

	setUpstreamProtocol(ctx, protoUDP)

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

	dnsConn := &dns.Conn{Conn: conn, UDPSize: uint16(currentMTU - ipUDPHeaderSize)}

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

// haMapRouteCount returns the total number of routes across all HA
// groups in the map. route.HAMap is keyed by HAUniqueID with slices of
// routes per key, so len(hm) is the number of HA groups, not routes.
func haMapRouteCount(hm route.HAMap) int {
	total := 0
	for _, routes := range hm {
		total += len(routes)
	}
	return total
}

// haMapContains checks whether ip is covered by any concrete prefix in
// the HA map. haveDynamic is reported separately: dynamic (domain-based)
// routes carry a placeholder Network that can't be prefix-checked, so we
// can't know at this point whether ip is reached through one. Callers
// decide how to interpret the unknown: health projection treats it as
// "possibly routed" to avoid emitting false-positive warnings during
// startup, while iOS dial selection requires a concrete match before
// binding to the tunnel.
func haMapContains(hm route.HAMap, ip netip.Addr) (matched, haveDynamic bool) {
	for _, routes := range hm {
		for _, r := range routes {
			if r.IsDynamic() {
				haveDynamic = true
				continue
			}
			if r.Network.Contains(ip) {
				return true, haveDynamic
			}
		}
	}
	return false, haveDynamic
}
