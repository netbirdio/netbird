package dnsinterceptor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/dnsfwd"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/client/internal/routemanager/common"
	"github.com/netbirdio/netbird/client/internal/routemanager/fakeip"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/route"
)

type domainMap map[domain.Domain][]netip.Prefix

type internalDNATer interface {
	RemoveInternalDNATMapping(netip.Addr) error
	AddInternalDNATMapping(netip.Addr, netip.Addr) error
}

type wgInterface interface {
	Name() string
	Address() wgaddr.Address
}

type DnsInterceptor struct {
	mu                   sync.RWMutex
	route                *route.Route
	routeRefCounter      *refcounter.RouteRefCounter
	allowedIPsRefcounter *refcounter.AllowedIPsRefCounter
	statusRecorder       *peer.Status
	dnsServer            nbdns.Server
	currentPeerKey       string
	interceptedDomains   domainMap
	wgInterface          wgInterface
	peerStore            *peerstore.Store
	firewall             firewall.Manager
	fakeIPManager        *fakeip.Manager
}

func New(params common.HandlerParams) *DnsInterceptor {
	return &DnsInterceptor{
		route:                params.Route,
		routeRefCounter:      params.RouteRefCounter,
		allowedIPsRefcounter: params.AllowedIPsRefCounter,
		statusRecorder:       params.StatusRecorder,
		dnsServer:            params.DnsServer,
		wgInterface:          params.WgInterface,
		peerStore:            params.PeerStore,
		firewall:             params.Firewall,
		fakeIPManager:        params.FakeIPManager,
		interceptedDomains:   make(domainMap),
	}
}

func (d *DnsInterceptor) String() string {
	return d.route.Domains.SafeString()
}

func (d *DnsInterceptor) AddRoute(context.Context) error {
	d.dnsServer.RegisterHandler(d.route.Domains, d, nbdns.PriorityDNSRoute)
	return nil
}

func (d *DnsInterceptor) RemoveRoute() error {
	d.mu.Lock()

	var merr *multierror.Error
	for domain, prefixes := range d.interceptedDomains {
		for _, prefix := range prefixes {
			// Routes should use fake IPs
			routePrefix := d.transformRealToFakePrefix(prefix)
			if _, err := d.routeRefCounter.Decrement(routePrefix); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("remove dynamic route for IP %s: %v", routePrefix, err))
			}

			// AllowedIPs should use real IPs
			if d.currentPeerKey != "" {
				if _, err := d.allowedIPsRefcounter.Decrement(prefix); err != nil {
					merr = multierror.Append(merr, fmt.Errorf("remove allowed IP %s: %v", prefix, err))
				}
			}
		}
		log.Debugf("removed dynamic route(s) for [%s]: %s", domain.SafeString(), strings.ReplaceAll(fmt.Sprintf("%s", prefixes), " ", ", "))
	}

	d.cleanupDNATMappings()

	for _, domain := range d.route.Domains {
		d.statusRecorder.DeleteResolvedDomainsStates(domain)
	}

	clear(d.interceptedDomains)
	d.mu.Unlock()

	d.dnsServer.DeregisterHandler(d.route.Domains, nbdns.PriorityDNSRoute)

	return nberrors.FormatErrorOrNil(merr)
}

// transformRealToFakePrefix returns fake IP prefix for routes (if DNAT enabled)
func (d *DnsInterceptor) transformRealToFakePrefix(realPrefix netip.Prefix) netip.Prefix {
	if _, hasDNAT := d.internalDnatFw(); !hasDNAT {
		return realPrefix
	}

	if fakeIP, ok := d.fakeIPManager.GetFakeIP(realPrefix.Addr()); ok {
		return netip.PrefixFrom(fakeIP, realPrefix.Bits())
	}

	return realPrefix
}

// addAllowedIPForPrefix handles the AllowedIPs logic for a single prefix (uses real IPs)
func (d *DnsInterceptor) addAllowedIPForPrefix(realPrefix netip.Prefix, peerKey string, domain domain.Domain) error {
	// AllowedIPs always use real IPs
	ref, err := d.allowedIPsRefcounter.Increment(realPrefix, peerKey)
	if err != nil {
		return fmt.Errorf("add allowed IP %s: %v", realPrefix, err)
	}

	if ref.Count > 1 && ref.Out != peerKey {
		log.Warnf("IP [%s] for domain [%s] is already routed by peer [%s]. HA routing disabled",
			realPrefix.Addr(),
			domain.SafeString(),
			ref.Out,
		)
	}

	return nil
}

// addRouteAndAllowedIP handles both route and AllowedIPs addition for a prefix
func (d *DnsInterceptor) addRouteAndAllowedIP(realPrefix netip.Prefix, domain domain.Domain) error {
	// Routes use fake IPs (so traffic to fake IPs gets routed to interface)
	routePrefix := d.transformRealToFakePrefix(realPrefix)
	if _, err := d.routeRefCounter.Increment(routePrefix, struct{}{}); err != nil {
		return fmt.Errorf("add route for IP %s: %v", routePrefix, err)
	}

	// Add to AllowedIPs if we have a current peer (uses real IPs)
	if d.currentPeerKey == "" {
		return nil
	}

	return d.addAllowedIPForPrefix(realPrefix, d.currentPeerKey, domain)
}

// removeAllowedIP handles AllowedIPs removal for a prefix (uses real IPs)
func (d *DnsInterceptor) removeAllowedIP(realPrefix netip.Prefix) error {
	if d.currentPeerKey == "" {
		return nil
	}

	// AllowedIPs use real IPs
	if _, err := d.allowedIPsRefcounter.Decrement(realPrefix); err != nil {
		return fmt.Errorf("remove allowed IP %s: %v", realPrefix, err)
	}

	return nil
}

func (d *DnsInterceptor) AddAllowedIPs(peerKey string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var merr *multierror.Error
	for domain, prefixes := range d.interceptedDomains {
		for _, prefix := range prefixes {
			// AllowedIPs use real IPs
			if err := d.addAllowedIPForPrefix(prefix, peerKey, domain); err != nil {
				merr = multierror.Append(merr, err)
			}
		}
	}

	d.currentPeerKey = peerKey
	return nberrors.FormatErrorOrNil(merr)
}

func (d *DnsInterceptor) RemoveAllowedIPs() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var merr *multierror.Error
	for _, prefixes := range d.interceptedDomains {
		for _, prefix := range prefixes {
			// AllowedIPs use real IPs
			if _, err := d.allowedIPsRefcounter.Decrement(prefix); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("remove allowed IP %s: %v", prefix, err))
			}
		}
	}

	d.currentPeerKey = ""
	return nberrors.FormatErrorOrNil(merr)
}

// ServeDNS implements the dns.Handler interface
func (d *DnsInterceptor) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	requestID := nbdns.GenerateRequestID()
	logger := log.WithField("request_id", requestID)

	if len(r.Question) == 0 {
		return
	}
	logger.Tracef("received DNS request for domain=%s type=%v class=%v",
		r.Question[0].Name, r.Question[0].Qtype, r.Question[0].Qclass)

	// pass if non A/AAAA query
	if r.Question[0].Qtype != dns.TypeA && r.Question[0].Qtype != dns.TypeAAAA {
		d.continueToNextHandler(w, r, logger, "non A/AAAA query")
		return
	}

	d.mu.RLock()
	peerKey := d.currentPeerKey
	d.mu.RUnlock()

	if peerKey == "" {
		d.writeDNSError(w, r, logger, "no current peer key")
		return
	}

	upstreamIP, err := d.getUpstreamIP(peerKey)
	if err != nil {
		d.writeDNSError(w, r, logger, fmt.Sprintf("get upstream IP: %v", err))
		return
	}

	client, err := nbdns.GetClientPrivate(d.wgInterface.Address().IP, d.wgInterface.Name(), nbdns.UpstreamTimeout)
	if err != nil {
		d.writeDNSError(w, r, logger, fmt.Sprintf("create DNS client: %v", err))
		return
	}

	if r.Extra == nil {
		r.MsgHdr.AuthenticatedData = true
	}

	upstream := fmt.Sprintf("%s:%d", upstreamIP.String(), dnsfwd.ListenPort)
	// Create context with timeout for DNS exchange
	ctx, cancel := context.WithTimeout(context.Background(), nbdns.UpstreamTimeout)
	defer cancel()

	startTime := time.Now()
	reply, _, err := nbdns.ExchangeWithFallback(ctx, client, r, upstream)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			elapsed := time.Since(startTime)
			peerInfo := d.debugPeerTimeout(upstreamIP, peerKey)
			logger.Errorf("peer DNS timeout after %v (timeout=%v) for domain=%s to peer %s (%s)%s - error: %v",
				elapsed.Truncate(time.Millisecond), nbdns.UpstreamTimeout, r.Question[0].Name, upstreamIP.String(), peerKey, peerInfo, err)
		} else {
			logger.Errorf("failed to exchange DNS request with %s (%s) for domain=%s: %v", upstreamIP.String(), peerKey, r.Question[0].Name, err)
		}
		if err := w.WriteMsg(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure, Id: r.Id}}); err != nil {
			logger.Errorf("failed writing DNS response: %v", err)
		}
		return
	}

	var answer []dns.RR
	if reply != nil {
		answer = reply.Answer
	}

	logger.Tracef("upstream %s (%s) DNS response for domain=%s answers=%v", upstreamIP.String(), peerKey, r.Question[0].Name, answer)

	reply.Id = r.Id
	if err := d.writeMsg(w, reply); err != nil {
		logger.Errorf("failed writing DNS response: %v", err)
	}
}

func (d *DnsInterceptor) writeDNSError(w dns.ResponseWriter, r *dns.Msg, logger *log.Entry, reason string) {
	logger.Warnf("failed to query upstream for domain=%s: %s", r.Question[0].Name, reason)

	resp := new(dns.Msg)
	resp.SetRcode(r, dns.RcodeServerFailure)
	if err := w.WriteMsg(resp); err != nil {
		logger.Errorf("failed to write DNS error response: %v", err)
	}
}

// continueToNextHandler signals the handler chain to try the next handler
func (d *DnsInterceptor) continueToNextHandler(w dns.ResponseWriter, r *dns.Msg, logger *log.Entry, reason string) {
	logger.Tracef("continuing to next handler for domain=%s reason=%s", r.Question[0].Name, reason)

	resp := new(dns.Msg)
	resp.SetRcode(r, dns.RcodeNameError)
	// Set Zero bit to signal handler chain to continue
	resp.MsgHdr.Zero = true
	if err := w.WriteMsg(resp); err != nil {
		logger.Errorf("failed writing DNS continue response: %v", err)
	}
}

func (d *DnsInterceptor) getUpstreamIP(peerKey string) (netip.Addr, error) {
	peerAllowedIP, exists := d.peerStore.AllowedIP(peerKey)
	if !exists {
		return netip.Addr{}, fmt.Errorf("peer connection not found for key: %s", peerKey)
	}
	return peerAllowedIP, nil
}

func (d *DnsInterceptor) writeMsg(w dns.ResponseWriter, r *dns.Msg) error {
	if r == nil {
		return fmt.Errorf("received nil DNS message")
	}

	if len(r.Answer) > 0 && len(r.Question) > 0 {
		origPattern := ""
		if writer, ok := w.(*nbdns.ResponseWriterChain); ok {
			origPattern = writer.GetOrigPattern()
		}

		resolvedDomain := domain.Domain(strings.ToLower(r.Question[0].Name))

		// already punycode via RegisterHandler()
		originalDomain := domain.Domain(origPattern)
		if originalDomain == "" {
			originalDomain = resolvedDomain
		}

		var newPrefixes []netip.Prefix
		for _, answer := range r.Answer {
			var ip netip.Addr
			switch rr := answer.(type) {
			case *dns.A:
				addr, ok := netip.AddrFromSlice(rr.A)
				if !ok {
					log.Tracef("failed to convert A record for domain=%s ip=%v", resolvedDomain, rr.A)
					continue
				}
				ip = addr
			case *dns.AAAA:
				addr, ok := netip.AddrFromSlice(rr.AAAA)
				if !ok {
					log.Tracef("failed to convert AAAA record for domain=%s ip=%v", resolvedDomain, rr.AAAA)
					continue
				}
				ip = addr
			default:
				continue
			}

			prefix := netip.PrefixFrom(ip.Unmap(), ip.BitLen())
			newPrefixes = append(newPrefixes, prefix)
		}

		if len(newPrefixes) > 0 {
			if err := d.updateDomainPrefixes(resolvedDomain, originalDomain, newPrefixes); err != nil {
				log.Errorf("failed to update domain prefixes: %v", err)
			}

			d.replaceIPsInDNSResponse(r, newPrefixes)
		}
	}

	if err := w.WriteMsg(r); err != nil {
		return fmt.Errorf("failed to write DNS response: %v", err)
	}

	return nil
}

// logPrefixChanges handles the logging for prefix changes
func (d *DnsInterceptor) logPrefixChanges(resolvedDomain, originalDomain domain.Domain, toAdd, toRemove []netip.Prefix) {
	if len(toAdd) > 0 {
		log.Debugf("added dynamic route(s) for domain=%s (pattern: domain=%s): %s",
			resolvedDomain.SafeString(),
			originalDomain.SafeString(),
			toAdd)
	}
	if len(toRemove) > 0 && !d.route.KeepRoute {
		log.Debugf("removed dynamic route(s) for domain=%s (pattern: domain=%s): %s",
			resolvedDomain.SafeString(),
			originalDomain.SafeString(),
			toRemove)
	}
}

func (d *DnsInterceptor) updateDomainPrefixes(resolvedDomain, originalDomain domain.Domain, newPrefixes []netip.Prefix) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	oldPrefixes := d.interceptedDomains[resolvedDomain]
	toAdd, toRemove := determinePrefixChanges(oldPrefixes, newPrefixes)

	var merr *multierror.Error
	var dnatMappings map[netip.Addr]netip.Addr

	// Handle DNAT mappings for new prefixes
	if _, hasDNAT := d.internalDnatFw(); hasDNAT {
		dnatMappings = make(map[netip.Addr]netip.Addr)
		for _, prefix := range toAdd {
			realIP := prefix.Addr()
			if fakeIP, err := d.fakeIPManager.AllocateFakeIP(realIP); err == nil {
				dnatMappings[fakeIP] = realIP
				log.Tracef("allocated fake IP %s for real IP %s", fakeIP, realIP)
			} else {
				log.Errorf("Failed to allocate fake IP for %s: %v", realIP, err)
			}
		}
	}

	// Add new prefixes
	for _, prefix := range toAdd {
		if err := d.addRouteAndAllowedIP(prefix, resolvedDomain); err != nil {
			merr = multierror.Append(merr, err)
		}
	}

	d.addDNATMappings(dnatMappings)

	if !d.route.KeepRoute {
		// Remove old prefixes
		for _, prefix := range toRemove {
			// Routes use fake IPs
			routePrefix := d.transformRealToFakePrefix(prefix)
			if _, err := d.routeRefCounter.Decrement(routePrefix); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("remove route for IP %s: %v", routePrefix, err))
			}
			// AllowedIPs use real IPs
			if err := d.removeAllowedIP(prefix); err != nil {
				merr = multierror.Append(merr, err)
			}
		}

		d.removeDNATMappings(toRemove)
	}

	// Update domain prefixes using resolved domain as key - store real IPs
	if len(toAdd) > 0 || len(toRemove) > 0 {
		if d.route.KeepRoute {
			// nolint:gocritic
			newPrefixes = append(oldPrefixes, toAdd...)
		}
		d.interceptedDomains[resolvedDomain] = newPrefixes
		originalDomain = domain.Domain(strings.TrimSuffix(string(originalDomain), "."))

		// Store real IPs for status (user-facing), not fake IPs
		d.statusRecorder.UpdateResolvedDomainsStates(originalDomain, resolvedDomain, newPrefixes, d.route.GetResourceID())

		d.logPrefixChanges(resolvedDomain, originalDomain, toAdd, toRemove)
	}

	return nberrors.FormatErrorOrNil(merr)
}

// removeDNATMappings removes DNAT mappings from the firewall for real IP prefixes
func (d *DnsInterceptor) removeDNATMappings(realPrefixes []netip.Prefix) {
	if len(realPrefixes) == 0 {
		return
	}

	dnatFirewall, ok := d.internalDnatFw()
	if !ok {
		return
	}

	for _, prefix := range realPrefixes {
		realIP := prefix.Addr()
		if fakeIP, exists := d.fakeIPManager.GetFakeIP(realIP); exists {
			if err := dnatFirewall.RemoveInternalDNATMapping(fakeIP); err != nil {
				log.Errorf("Failed to remove DNAT mapping for %s: %v", fakeIP, err)
			} else {
				log.Debugf("Removed DNAT mapping for: %s -> %s", fakeIP, realIP)
			}
		}
	}
}

// internalDnatFw checks if the firewall supports internal DNAT
func (d *DnsInterceptor) internalDnatFw() (internalDNATer, bool) {
	if d.firewall == nil || runtime.GOOS != "android" {
		return nil, false
	}
	fw, ok := d.firewall.(internalDNATer)
	return fw, ok
}

// addDNATMappings adds DNAT mappings to the firewall
func (d *DnsInterceptor) addDNATMappings(mappings map[netip.Addr]netip.Addr) {
	if len(mappings) == 0 {
		return
	}

	dnatFirewall, ok := d.internalDnatFw()
	if !ok {
		return
	}

	for fakeIP, realIP := range mappings {
		if err := dnatFirewall.AddInternalDNATMapping(fakeIP, realIP); err != nil {
			log.Errorf("Failed to add DNAT mapping %s -> %s: %v", fakeIP, realIP, err)
		} else {
			log.Debugf("Added DNAT mapping: %s -> %s", fakeIP, realIP)
		}
	}
}

// cleanupDNATMappings removes all DNAT mappings for this interceptor
func (d *DnsInterceptor) cleanupDNATMappings() {
	if _, ok := d.internalDnatFw(); !ok {
		return
	}

	for _, prefixes := range d.interceptedDomains {
		d.removeDNATMappings(prefixes)
	}
}

// replaceIPsInDNSResponse replaces real IPs with fake IPs in the DNS response
func (d *DnsInterceptor) replaceIPsInDNSResponse(reply *dns.Msg, realPrefixes []netip.Prefix) {
	if _, ok := d.internalDnatFw(); !ok {
		return
	}

	// Replace A and AAAA records with fake IPs
	for _, answer := range reply.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			realIP, ok := netip.AddrFromSlice(rr.A)
			if !ok {
				continue
			}

			if fakeIP, exists := d.fakeIPManager.GetFakeIP(realIP); exists {
				rr.A = fakeIP.AsSlice()
				log.Tracef("Replaced real IP %s with fake IP %s in DNS response", realIP, fakeIP)
			}

		case *dns.AAAA:
			realIP, ok := netip.AddrFromSlice(rr.AAAA)
			if !ok {
				continue
			}

			if fakeIP, exists := d.fakeIPManager.GetFakeIP(realIP); exists {
				rr.AAAA = fakeIP.AsSlice()
				log.Tracef("Replaced real IP %s with fake IP %s in DNS response", realIP, fakeIP)
			}
		}
	}
}

func determinePrefixChanges(oldPrefixes, newPrefixes []netip.Prefix) (toAdd, toRemove []netip.Prefix) {
	prefixSet := make(map[netip.Prefix]bool)
	for _, prefix := range oldPrefixes {
		prefixSet[prefix] = false
	}
	for _, prefix := range newPrefixes {
		if _, exists := prefixSet[prefix]; exists {
			prefixSet[prefix] = true
		} else {
			toAdd = append(toAdd, prefix)
		}
	}
	for prefix, inUse := range prefixSet {
		if !inUse {
			toRemove = append(toRemove, prefix)
		}
	}
	return
}

// debugPeerTimeout provides debugging information when a peer DNS request times out.
func (d *DnsInterceptor) debugPeerTimeout(peerIP netip.Addr, peerKey string) string {
	if d.statusRecorder == nil {
		return ""
	}

	// Get peer state from status recorder
	peerState, err := d.statusRecorder.GetPeer(peerKey)
	if err != nil {
		return fmt.Sprintf(" (peer %s state error: %v)", peerKey[:8], err)
	}

	// Check peer connection status
	isConnected := peerState.ConnStatus == peer.StatusConnected
	hasRecentHandshake := !peerState.LastWireguardHandshake.IsZero() &&
		time.Since(peerState.LastWireguardHandshake) < 3*time.Minute

	// Build concise status info
	statusInfo := fmt.Sprintf(" (peer %s:%s", peerState.FQDN, peerState.IP)

	if !isConnected {
		statusInfo += " DISCONNECTED"
	} else if !hasRecentHandshake {
		statusInfo += " NO_RECENT_HANDSHAKE"
	} else {
		statusInfo += " connected"
	}

	// Add handshake timing information
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

	statusInfo += ")"
	return statusInfo
}
