package dnsinterceptor

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
)

type DnsInterceptor struct {
	mu                   sync.RWMutex
	route                *route.Route
	routeRefCounter      *refcounter.RouteRefCounter
	allowedIPsRefcounter *refcounter.AllowedIPsRefCounter
	statusRecorder       *peer.Status
	dnsServer            nbdns.Server
	currentPeerKey       string
	interceptedIPs       map[string]netip.Prefix
	peerConns            map[string]*peer.Conn
}

func New(
	rt *route.Route,
	routeRefCounter *refcounter.RouteRefCounter,
	allowedIPsRefCounter *refcounter.AllowedIPsRefCounter,
	statusRecorder *peer.Status,
	dnsServer nbdns.Server,
	peerConns map[string]*peer.Conn,
) *DnsInterceptor {
	return &DnsInterceptor{
		route:                rt,
		routeRefCounter:      routeRefCounter,
		allowedIPsRefcounter: allowedIPsRefCounter,
		statusRecorder:       statusRecorder,
		dnsServer:            dnsServer,
		interceptedIPs:       make(map[string]netip.Prefix),
		peerConns:            peerConns,
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

	// Remove all intercepted IPs
	for key, prefix := range d.interceptedIPs {
		if _, err := d.routeRefCounter.Decrement(prefix); err != nil {
			log.Errorf("Failed to remove route for IP %s: %v", prefix, err)
		}
		if d.currentPeerKey != "" {
			if _, err := d.allowedIPsRefcounter.Decrement(prefix); err != nil {
				log.Errorf("Failed to remove allowed IP %s: %v", prefix, err)
			}
		}
		delete(d.interceptedIPs, key)
	}

	// TODO: remove from mux

	return nil
}

func (d *DnsInterceptor) AddAllowedIPs(peerKey string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.currentPeerKey = peerKey

	// Re-add all intercepted IPs for the new peer
	for _, prefix := range d.interceptedIPs {
		if _, err := d.allowedIPsRefcounter.Increment(prefix, peerKey); err != nil {
			log.Errorf("Failed to add allowed IP %s: %v", prefix, err)
		}
	}

	return nil
}

func (d *DnsInterceptor) RemoveAllowedIPs() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.currentPeerKey != "" {
		for _, prefix := range d.interceptedIPs {
			if _, err := d.allowedIPsRefcounter.Decrement(prefix); err != nil {
				log.Errorf("Failed to remove allowed IP %s: %v", prefix, err)
			}
		}
	}

	d.currentPeerKey = ""
	return nil
}

// ServeDNS implements the dns.Handler interface
func (d *DnsInterceptor) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	log.Debugf("received DNS request: %v", r)
	if len(r.Question) == 0 {
		return
	}

	if err := d.writeMsg(w, r); err != nil {
		log.Errorf("failed writing DNS response: %v", err)
	}
}

func (d *DnsInterceptor) writeMsg(w dns.ResponseWriter, r *dns.Msg) error {
	if r == nil || len(r.Answer) == 0 {
		return w.WriteMsg(r)
	}

	for _, ans := range r.Answer {
		var ip netip.Addr
		switch rr := ans.(type) {
		case *dns.A:
			addr, ok := netip.AddrFromSlice(rr.A)
			if !ok {
				continue
			}
			ip = addr
		case *dns.AAAA:
			addr, ok := netip.AddrFromSlice(rr.AAAA)
			if !ok {
				continue
			}
			ip = addr
		default:
			continue
		}

		d.processMatch(r.Question[0].Name, ip)
	}

	return w.WriteMsg(r)
}

func (d *DnsInterceptor) processMatch(domain string, ip netip.Addr) {
	d.mu.Lock()
	defer d.mu.Unlock()

	network := netip.PrefixFrom(ip, ip.BitLen())
	key := fmt.Sprintf("%s:%s", domain, network.String())

	if _, exists := d.interceptedIPs[key]; exists {
		return
	}

	if _, err := d.routeRefCounter.Increment(network, struct{}{}); err != nil {
		log.Errorf("Failed to add route for IP %s: %v", network, err)
		return
	}

	if d.currentPeerKey != "" {
		if _, err := d.allowedIPsRefcounter.Increment(network, d.currentPeerKey); err != nil {
			log.Errorf("Failed to add allowed IP %s: %v", network, err)
			// Rollback route addition
			if _, err := d.routeRefCounter.Decrement(network); err != nil {
				log.Errorf("Failed to rollback route addition for IP %s: %v", network, err)
			}
			return
		}
	}

	d.interceptedIPs[key] = network
	log.Debugf("Added route for domain %s -> %s", domain, network)
}
