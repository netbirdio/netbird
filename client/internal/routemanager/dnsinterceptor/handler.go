package dnsinterceptor

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
)

type RouteMatchHandler struct {
	mu                   sync.RWMutex
	route                *route.Route
	routeRefCounter      *refcounter.RouteRefCounter
	allowedIPsRefcounter *refcounter.AllowedIPsRefCounter
	statusRecorder       *peer.Status
	dnsServer            nbdns.Server
	currentPeerKey       string
	domainRoutes         map[string]*route.Route
}

func New(
	rt *route.Route,
	routeRefCounter *refcounter.RouteRefCounter,
	allowedIPsRefCounter *refcounter.AllowedIPsRefCounter,
	statusRecorder *peer.Status,
	dnsServer nbdns.Server,
) routemanager.RouteHandler {

	return &RouteMatchHandler{
		route:                rt,
		routeRefCounter:      routeRefCounter,
		allowedIPsRefcounter: allowedIPsRefCounter,
		statusRecorder:       statusRecorder,
		dnsServer:            dnsServer,
		domainRoutes:         make(map[string]*route.Route),
	}
}

func (h *RouteMatchHandler) String() string {
	return fmt.Sprintf("dns route for domains: %v", h.route.Domains)
}

func (h *RouteMatchHandler) AddRoute(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, domain := range h.route.Domains {
		pattern := dns.Fqdn(string(domain))
		h.domainRoutes[pattern] = h.route
	}

	return h.dnsServer.RegisterHandler(h)
}

func (h *RouteMatchHandler) RemoveRoute() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.domainRoutes = make(map[string]*route.Route)
	return nil
}

func (h *RouteMatchHandler) AddAllowedIPs(peerKey string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.currentPeerKey = peerKey
	return nil
}

func (h *RouteMatchHandler) RemoveAllowedIPs() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.currentPeerKey = ""
	return nil
}

type responseInterceptor struct {
	dns.ResponseWriter
	handler  *RouteMatchHandler
	question dns.Question
	answered bool
}

func (i *responseInterceptor) WriteMsg(resp *dns.Msg) error {
	if i.answered {
		return nil
	}
	i.answered = true

	if resp == nil || len(resp.Answer) == 0 {
		return i.ResponseWriter.WriteMsg(resp)
	}

	i.handler.mu.RLock()
	defer i.handler.mu.RUnlock()

	questionName := i.question.Name
	for _, ans := range resp.Answer {
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

		if route := i.handler.findMatchingRoute(questionName); route != nil {
			i.handler.processMatch(route, questionName, ip)
		}
	}

	return i.ResponseWriter.WriteMsg(resp)
}

func (h *RouteMatchHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	interceptor := &responseInterceptor{
		ResponseWriter: w,
		handler:        h,
		question:       r.Question[0],
	}

	h.dnsServer.ServeDNS(interceptor, r)
}

func (h *RouteMatchHandler) findMatchingRoute(domain string) *route.Route {
	domain = strings.ToLower(domain)

	if route, ok := h.domainRoutes[domain]; ok {
		return route
	}

	labels := dns.SplitDomainName(domain)
	if labels == nil {
		return nil
	}

	for i := 0; i < len(labels); i++ {
		wildcard := "*." + strings.Join(labels[i:], ".") + "."
		if route, ok := h.domainRoutes[wildcard]; ok {
			return route
		}
	}

	return nil
}

func (h *RouteMatchHandler) processMatch(route *route.Route, domain string, ip netip.Addr) {
	network := netip.PrefixFrom(ip, ip.BitLen())

	if h.currentPeerKey == "" {
		return
	}

	if err := h.allowedIPsRefcounter.Increment(network, h.currentPeerKey); err != nil {
		log.Errorf("Failed to add allowed IP %s: %v", network, err)
	}
}
