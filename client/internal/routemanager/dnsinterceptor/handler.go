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
}

func New(
	rt *route.Route,
	routeRefCounter *refcounter.RouteRefCounter,
	allowedIPsRefCounter *refcounter.AllowedIPsRefCounter,
	statusRecorder *peer.Status,
	dnsServer nbdns.Server,
) *DnsInterceptor {
	return &DnsInterceptor{
		route:                rt,
		routeRefCounter:      routeRefCounter,
		allowedIPsRefcounter: allowedIPsRefCounter,
		statusRecorder:       statusRecorder,
		dnsServer:            dnsServer,
		interceptedIPs:       make(map[string]netip.Prefix),
	}
}

func (h *DnsInterceptor) String() string {
	s, err := h.route.Domains.String()
	if err != nil {
		return h.route.Domains.PunycodeString()
	}
	return s
}

func (h *DnsInterceptor) AddRoute(context.Context) error {
	return h.dnsServer.RegisterHandler(h.route.Domains.ToPunycodeList(), h)
}

func (h *DnsInterceptor) RemoveRoute() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Remove all intercepted IPs
	for key, prefix := range h.interceptedIPs {
		if _, err := h.routeRefCounter.Decrement(prefix); err != nil {
			log.Errorf("Failed to remove route for IP %s: %v", prefix, err)
		}
		if h.currentPeerKey != "" {
			if _, err := h.allowedIPsRefcounter.Decrement(prefix); err != nil {
				log.Errorf("Failed to remove allowed IP %s: %v", prefix, err)
			}
		}
		delete(h.interceptedIPs, key)
	}

	// TODO: remove from mux

	return nil
}

func (h *DnsInterceptor) AddAllowedIPs(peerKey string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.currentPeerKey = peerKey

	// Re-add all intercepted IPs for the new peer
	for _, prefix := range h.interceptedIPs {
		if _, err := h.allowedIPsRefcounter.Increment(prefix, peerKey); err != nil {
			log.Errorf("Failed to add allowed IP %s: %v", prefix, err)
		}
	}

	return nil
}

func (h *DnsInterceptor) RemoveAllowedIPs() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.currentPeerKey != "" {
		for _, prefix := range h.interceptedIPs {
			if _, err := h.allowedIPsRefcounter.Decrement(prefix); err != nil {
				log.Errorf("Failed to remove allowed IP %s: %v", prefix, err)
			}
		}
	}

	h.currentPeerKey = ""
	return nil
}

// ServeDNS implements the dns.Handler interface
func (h *DnsInterceptor) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	log.Debugf("Received DNS request: %v", r)
	if len(r.Question) == 0 {
		return
	}

	// Create response interceptor to capture the response
	interceptor := &responseInterceptor{
		ResponseWriter: w,
		handler:        h,
		question:       r.Question[0],
		answered:       false,
	}

	// Let the request pass through with our interceptor
	err := interceptor.WriteMsg(r)
	if err != nil {
		log.Errorf("Failed writing DNS response: %v", err)
	}
}

func (h *DnsInterceptor) processMatch(domain string, ip netip.Addr) {
	h.mu.Lock()
	defer h.mu.Unlock()

	network := netip.PrefixFrom(ip, ip.BitLen())
	key := fmt.Sprintf("%s:%s", domain, network.String())

	if _, exists := h.interceptedIPs[key]; exists {
		return
	}

	if _, err := h.routeRefCounter.Increment(network, struct{}{}); err != nil {
		log.Errorf("Failed to add route for IP %s: %v", network, err)
		return
	}

	if h.currentPeerKey != "" {
		if _, err := h.allowedIPsRefcounter.Increment(network, h.currentPeerKey); err != nil {
			log.Errorf("Failed to add allowed IP %s: %v", network, err)
			// Rollback route addition
			if _, err := h.routeRefCounter.Decrement(network); err != nil {
				log.Errorf("Failed to rollback route addition for IP %s: %v", network, err)
			}
			return
		}
	}

	h.interceptedIPs[key] = network
	log.Debugf("Added route for domain %s -> %s", domain, network)
}
