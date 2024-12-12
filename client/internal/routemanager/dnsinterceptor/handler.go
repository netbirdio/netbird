package dnsinterceptor

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

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
	s, err := d.route.Domains.String()
	if err != nil {
		return d.route.Domains.PunycodeString()
	}
	return s
}

func (d *DnsInterceptor) AddRoute(context.Context) error {
	return d.dnsServer.RegisterHandler(d.route.Domains.ToPunycodeList(), d)
}

func (d *DnsInterceptor) RemoveRoute() error {
	d.mu.Lock()
	defer d.mu.Unlock()

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

		d.statusRecorder.DeleteResolvedDomainsStates(domain)
	}

	clear(d.interceptedDomains)

	if err := d.dnsServer.DeregisterHandler(d.route.Domains.ToPunycodeList()); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("unregister DNS handler: %v", err))
	}

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
	log.Debugf("received DNS request: %v", r.Question[0].Name)

	if d.currentPeerKey == "" {
		// TODO: call normal upstream instead of returning an error?
		log.Debugf("no current peer key set, not resolving DNS request %s", r.Question[0].Name)
		if err := w.WriteMsg(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure, Id: r.Id}}); err != nil {
			log.Errorf("failed writing DNS response: %v", err)
		}
		return
	}

	upstreamIP, err := d.getUpstreamIP()
	if err != nil {
		log.Errorf("failed to get upstream IP: %v", err)
		if err := w.WriteMsg(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure, Id: r.Id}}); err != nil {
			log.Errorf("failed writing DNS response: %v", err)
		}
		return
	}

	client := &dns.Client{
		Timeout: 5 * time.Second,
		Net:     "udp",
	}
	upstream := fmt.Sprintf("%s:%d", upstreamIP, dnsfwd.ListenPort)
	reply, _, err := client.ExchangeContext(context.Background(), r, upstream)
	log.Debugf("upstream %s (%s) DNS response for %s: %v", upstreamIP, d.currentPeerKey, r.Question[0].Name, reply.Answer)

	if err != nil {
		log.Errorf("failed to exchange DNS request with %s: %v", upstream, err)
		if err := w.WriteMsg(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure, Id: r.Id}}); err != nil {
			log.Errorf("failed writing DNS response: %v", err)
		}
		return
	}

	reply.Id = r.Id
	if err := d.writeMsg(w, reply); err != nil {
		log.Errorf("failed writing DNS response: %v", err)
	}
}

func (d *DnsInterceptor) getUpstreamIP() (net.IP, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	peerAllowedIP, exists := d.peerStore.AllowedIP(d.currentPeerKey)
	if !exists {
		return nil, fmt.Errorf("peer connection not found for key: %s", d.currentPeerKey)
	}
	return peerAllowedIP, nil
}

func (d *DnsInterceptor) writeMsg(w dns.ResponseWriter, r *dns.Msg) error {
	if r == nil {
		return fmt.Errorf("received nil DNS message")
	}

	if len(r.Answer) > 0 && len(r.Question) > 0 {
		// DNS names from miekg/dns are already in punycode format
		dom := domain.Domain(r.Question[0].Name)

		var newPrefixes []netip.Prefix
		for _, answer := range r.Answer {
			var ip netip.Addr
			switch rr := answer.(type) {
			case *dns.A:
				addr, ok := netip.AddrFromSlice(rr.A)
				if !ok {
					log.Debugf("failed to convert A record IP: %v", rr.A)
					continue
				}
				ip = addr
			case *dns.AAAA:
				addr, ok := netip.AddrFromSlice(rr.AAAA)
				if !ok {
					log.Debugf("failed to convert AAAA record IP: %v", rr.AAAA)
					continue
				}
				ip = addr
			default:
				continue
			}

			prefix := netip.PrefixFrom(ip, ip.BitLen())
			newPrefixes = append(newPrefixes, prefix)
		}

		if len(newPrefixes) > 0 {
			if err := d.updateDomainPrefixes(dom, newPrefixes); err != nil {
				log.Errorf("failed to update domain prefixes: %v", err)
			}
		}
	}

	if err := w.WriteMsg(r); err != nil {
		return fmt.Errorf("failed to write DNS response: %v", err)
	}

	return nil
}

func (d *DnsInterceptor) updateDomainPrefixes(domain domain.Domain, newPrefixes []netip.Prefix) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	oldPrefixes := d.interceptedDomains[domain]
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
				domain.SafeString(),
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

	// Update domain prefixes
	if len(toAdd) > 0 || len(toRemove) > 0 {
		d.interceptedDomains[domain] = newPrefixes
		d.statusRecorder.UpdateResolvedDomainsStates(domain, newPrefixes)

		if len(toAdd) > 0 {
			log.Debugf("added dynamic route(s) for [%s]: %s", domain.SafeString(), toAdd)
		}
		if len(toRemove) > 0 {
			log.Debugf("removed dynamic route(s) for [%s]: %s", domain.SafeString(), toRemove)
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
