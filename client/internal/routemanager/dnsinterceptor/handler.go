package dnsinterceptor

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/dnsfwd"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/route"
)

type domainMap map[domain.Domain][]netip.Prefix

type DnsInterceptor struct {
	mu                   sync.RWMutex
	route                *route.Route
	routeRefCounter      *refcounter.RouteRefCounter
	allowedIPsRefcounter *refcounter.AllowedIPsRefCounter
	statusRecorder       *peer.Status
	dnsServer            nbdns.Server
	currentPeerKey       string
	interceptedDomains   domainMap
	peerStore            *peerstore.Store
}

func New(
	rt *route.Route,
	routeRefCounter *refcounter.RouteRefCounter,
	allowedIPsRefCounter *refcounter.AllowedIPsRefCounter,
	statusRecorder *peer.Status,
	dnsServer nbdns.Server,
	peerStore *peerstore.Store,
) *DnsInterceptor {
	return &DnsInterceptor{
		route:                rt,
		routeRefCounter:      routeRefCounter,
		allowedIPsRefcounter: allowedIPsRefCounter,
		statusRecorder:       statusRecorder,
		dnsServer:            dnsServer,
		interceptedDomains:   make(domainMap),
		peerStore:            peerStore,
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
			if _, err := d.routeRefCounter.Decrement(prefix); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("remove dynamic route for IP %s: %v", prefix, err))
			}
			if d.currentPeerKey != "" {
				if _, err := d.allowedIPsRefcounter.Decrement(prefix); err != nil {
					merr = multierror.Append(merr, fmt.Errorf("remove allowed IP %s: %v", prefix, err))
				}
			}
		}
		log.Debugf("removed dynamic route(s) for [%s]: %s", domain.SafeString(), strings.ReplaceAll(fmt.Sprintf("%s", prefixes), " ", ", "))

	}
	for _, domain := range d.route.Domains {
		d.statusRecorder.DeleteResolvedDomainsStates(domain)
	}

	clear(d.interceptedDomains)
	d.mu.Unlock()

	d.dnsServer.DeregisterHandler(d.route.Domains, nbdns.PriorityDNSRoute)

	return nberrors.FormatErrorOrNil(merr)
}

func (d *DnsInterceptor) AddAllowedIPs(peerKey string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var merr *multierror.Error
	for domain, prefixes := range d.interceptedDomains {
		for _, prefix := range prefixes {
			if ref, err := d.allowedIPsRefcounter.Increment(prefix, peerKey); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("add allowed IP %s: %v", prefix, err))
			} else if ref.Count > 1 && ref.Out != peerKey {
				log.Warnf("IP [%s] for domain [%s] is already routed by peer [%s]. HA routing disabled",
					prefix.Addr(),
					domain.SafeString(),
					ref.Out,
				)
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
	if len(r.Question) == 0 {
		return
	}
	log.Tracef("received DNS request for domain=%s type=%v class=%v",
		r.Question[0].Name, r.Question[0].Qtype, r.Question[0].Qclass)

	// pass if non A/AAAA query
	if r.Question[0].Qtype != dns.TypeA && r.Question[0].Qtype != dns.TypeAAAA {
		d.continueToNextHandler(w, r, "non A/AAAA query")
		return
	}

	d.mu.RLock()
	peerKey := d.currentPeerKey
	d.mu.RUnlock()

	if peerKey == "" {
		d.writeDNSError(w, r, "no current peer key")
		return
	}

	upstreamIP, err := d.getUpstreamIP(peerKey)
	if err != nil {
		d.writeDNSError(w, r, fmt.Sprintf("get upstream IP: %v", err))
		return
	}

	if r.Extra == nil {
		r.MsgHdr.AuthenticatedData = true
	}
	client := &dns.Client{
		Timeout: nbdns.UpstreamTimeout,
		Net:     "udp",
	}
	upstream := fmt.Sprintf("%s:%d", upstreamIP.String(), dnsfwd.ListenPort)
	reply, _, err := nbdns.ExchangeWithFallback(context.TODO(), client, r, upstream)
	if err != nil {
		log.Errorf("failed to exchange DNS request with %s (%s) for domain=%s: %v", upstreamIP.String(), peerKey, r.Question[0].Name, err)
		if err := w.WriteMsg(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure, Id: r.Id}}); err != nil {
			log.Errorf("failed writing DNS response: %v", err)
		}
		return
	}

	var answer []dns.RR
	if reply != nil {
		answer = reply.Answer
	}

	log.Tracef("upstream %s (%s) DNS response for domain=%s answers=%v", upstreamIP.String(), peerKey, r.Question[0].Name, answer)

	reply.Id = r.Id
	if err := d.writeMsg(w, reply); err != nil {
		log.Errorf("failed writing DNS response: %v", err)
	}
}

func (d *DnsInterceptor) writeDNSError(w dns.ResponseWriter, r *dns.Msg, reason string) {
	log.Warnf("failed to query upstream for domain=%s: %s", r.Question[0].Name, reason)

	resp := new(dns.Msg)
	resp.SetRcode(r, dns.RcodeServerFailure)
	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed to write DNS error response: %v", err)
	}
}

// continueToNextHandler signals the handler chain to try the next handler
func (d *DnsInterceptor) continueToNextHandler(w dns.ResponseWriter, r *dns.Msg, reason string) {
	log.Tracef("continuing to next handler for domain=%s reason=%s", r.Question[0].Name, reason)

	resp := new(dns.Msg)
	resp.SetRcode(r, dns.RcodeNameError)
	// Set Zero bit to signal handler chain to continue
	resp.MsgHdr.Zero = true
	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed writing DNS continue response: %v", err)
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
		var origPattern domain.Domain
		if writer, ok := w.(*nbdns.ResponseWriterChain); ok {
			origPattern = writer.GetOrigPattern()
		}

		resolvedDomain := domain.Domain(strings.ToLower(r.Question[0].Name))

		originalDomain := origPattern
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
		}
	}

	if err := w.WriteMsg(r); err != nil {
		return fmt.Errorf("failed to write DNS response: %v", err)
	}

	return nil
}

func (d *DnsInterceptor) updateDomainPrefixes(resolvedDomain, originalDomain domain.Domain, newPrefixes []netip.Prefix) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	oldPrefixes := d.interceptedDomains[resolvedDomain]
	toAdd, toRemove := determinePrefixChanges(oldPrefixes, newPrefixes)

	var merr *multierror.Error

	// Add new prefixes
	for _, prefix := range toAdd {
		if _, err := d.routeRefCounter.Increment(prefix, struct{}{}); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("add route for IP %s: %v", prefix, err))
			continue
		}

		if d.currentPeerKey == "" {
			continue
		}
		if ref, err := d.allowedIPsRefcounter.Increment(prefix, d.currentPeerKey); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("add allowed IP %s: %v", prefix, err))
		} else if ref.Count > 1 && ref.Out != d.currentPeerKey {
			log.Warnf("IP [%s] for domain [%s] is already routed by peer [%s]. HA routing disabled",
				prefix.Addr(),
				resolvedDomain.SafeString(),
				ref.Out,
			)
		}
	}

	if !d.route.KeepRoute {
		// Remove old prefixes
		for _, prefix := range toRemove {
			if _, err := d.routeRefCounter.Decrement(prefix); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("remove route for IP %s: %v", prefix, err))
			}
			if d.currentPeerKey != "" {
				if _, err := d.allowedIPsRefcounter.Decrement(prefix); err != nil {
					merr = multierror.Append(merr, fmt.Errorf("remove allowed IP %s: %v", prefix, err))
				}
			}
		}
	}

	// Update domain prefixes using resolved domain as key
	if len(toAdd) > 0 || len(toRemove) > 0 {
		if d.route.KeepRoute {
			// replace stored prefixes with old + added
			// nolint:gocritic
			newPrefixes = append(oldPrefixes, toAdd...)
		}
		d.interceptedDomains[resolvedDomain] = newPrefixes
		originalDomain = domain.Domain(strings.TrimSuffix(string(originalDomain), "."))
		d.statusRecorder.UpdateResolvedDomainsStates(originalDomain, resolvedDomain, newPrefixes, d.route.GetResourceID())

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

	return nberrors.FormatErrorOrNil(merr)
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
