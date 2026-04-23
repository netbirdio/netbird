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
	"github.com/netbirdio/netbird/client/internal/dns/resutil"
	"github.com/netbirdio/netbird/client/internal/dns/types"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
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

// contextWithupstreamProtocolResult stores a mutable result holder in the context.
func contextWithupstreamProtocolResult(ctx context.Context) (context.Context, *upstreamProtocolResult) {
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

// ID returns the unique handler ID
func (u *upstreamResolverBase) ID() types.HandlerID {
	servers := u.flatUpstreams()
	slices.SortFunc(servers, func(a, b netip.AddrPort) int { return a.Compare(b) })

	hash := sha256.New()
	hash.Write([]byte(u.domain.PunycodeString() + ":"))
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

// isRouted reports whether ip falls inside any client route the admin
// has selected.
func (u *upstreamResolverBase) isRouted(ip netip.Addr) bool {
	if u.selectedRoutes == nil {
		return false
	}
	return haMapContains(u.selectedRoutes(), ip)
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
		timeout = max(raceMaxTotalTimeout/time.Duration(len(group)), raceMinPerUpstreamTimeout)
	}

	var failures []upstreamFailure
	for _, upstream := range group {
		if ctx.Err() != nil {
			return raceResult{failures: failures}
		}
		msg, proto, failure := u.queryUpstream(ctx, r, upstream, timeout)
		if failure != nil {
			failures = append(failures, *failure)
			continue
		}
		return raceResult{msg: msg, upstream: upstream, protocol: proto, failures: failures}
	}
	return raceResult{failures: failures}
}

func (u *upstreamResolverBase) queryUpstream(parentCtx context.Context, r *dns.Msg, upstream netip.AddrPort, timeout time.Duration) (*dns.Msg, string, *upstreamFailure) {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	ctx, upstreamProto := contextWithupstreamProtocolResult(ctx)

	startTime := time.Now()
	rm, _, err := u.upstreamClient.exchange(ctx, upstream.String(), r)

	if err != nil {
		failure := u.handleUpstreamError(err, upstream, startTime)
		u.markUpstreamFail(upstream, failure.reason)
		return nil, "", failure
	}

	if rm == nil || !rm.Response {
		u.markUpstreamFail(upstream, "no response")
		return nil, "", &upstreamFailure{upstream: upstream, reason: "no response"}
	}

	if rm.Rcode == dns.RcodeServerFailure || rm.Rcode == dns.RcodeRefused {
		reason := dns.RcodeToString[rm.Rcode]
		u.markUpstreamFail(upstream, reason)
		return nil, "", &upstreamFailure{upstream: upstream, reason: reason}
	}

	u.markUpstreamOk(upstream)

	proto := ""
	if upstreamProto != nil {
		proto = upstreamProto.protocol
	}
	return rm, proto, nil
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
// If the passed context is nil, this will use Exchange instead of ExchangeContext.
func ExchangeWithFallback(ctx context.Context, client *dns.Client, r *dns.Msg, upstream string) (*dns.Msg, time.Duration, error) {
	// If the request came in over TCP, go straight to TCP upstream.
	if dnsProtocolFromContext(ctx) == protoTCP {
		tcpClient := *client
		tcpClient.Net = protoTCP
		rm, t, err := tcpClient.ExchangeContext(ctx, r, upstream)
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
		setUpstreamProtocol(ctx, protoUDP)
		return rm, t, nil
	}

	// TODO: if the upstream's truncated UDP response already contains more
	// data than the client's buffer, we could truncate locally and skip
	// the TCP retry.

	tcpClient := *client
	tcpClient.Net = protoTCP

	if ctx == nil {
		rm, t, err = tcpClient.Exchange(r, upstream)
	} else {
		rm, t, err = tcpClient.ExchangeContext(ctx, r, upstream)
	}

	if err != nil {
		return nil, t, fmt.Errorf("with tcp: %w", err)
	}

	setUpstreamProtocol(ctx, protoTCP)

	if rm.Len() > clientMaxSize {
		rm.Truncate(clientMaxSize)
	}

	return rm, t, nil
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

// haMapContains reports whether any route in the map contains ip.
//
// Gap: dynamic (domain-based) routes carry a placeholder Network that
// never matches a real address, so an upstream reached via a dynamic
// route is classified as "not routed" here. The DNS health path then
// emits failure events immediately for such upstreams instead of
// applying the startup grace window. Rare (DNS servers are usually
// designated by IP, not by domain) but worth revisiting if DoT/DoH-style
// upstreams or /etc/hosts-style domain routing to DNS become supported.
func haMapContains(hm route.HAMap, ip netip.Addr) bool {
	for _, routes := range hm {
		for _, r := range routes {
			if r.Network.Contains(ip) {
				return true
			}
		}
	}
	return false
}
