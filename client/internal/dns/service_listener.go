package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

const (
	customPort = 5053
	// randomPortAttempts bounds the search for a port free on both protocols.
	randomPortAttempts = 5
)

var (
	defaultIP = netip.MustParseAddr("127.0.0.1")
	customIP  = netip.MustParseAddr("127.0.0.153")

	// dnatProtocols are the protocols the port 53 redirect covers.
	dnatProtocols = []firewall.Protocol{firewall.ProtocolUDP, firewall.ProtocolTCP}
)

type serviceViaListener struct {
	wgInterface       WGIface
	dnsMux            *dns.ServeMux
	customAddr        *netip.AddrPort
	server            *dns.Server
	tcpServer         *dns.Server
	listenIP          netip.Addr
	listenPort        uint16
	listenerIsRunning bool
	listenerFlagLock  sync.Mutex
	firewall          Firewall
	// dnatRules holds the port 53 redirects that are installed and not yet
	// removed, so a removal that fails can be retried.
	dnatRules []dnatRule
}

// dnatRule is a port 53 redirect as it was installed. The target is kept with
// the rule because the listener can come back on a different address or port,
// and a retried removal has to name the address and port the rule was added
// with, not the ones in use now.
type dnatRule struct {
	protocol firewall.Protocol
	ip       netip.Addr
	port     uint16
}

func newServiceViaListener(wgIface WGIface, customAddr *netip.AddrPort, fw Firewall) *serviceViaListener {
	mux := dns.NewServeMux()

	s := &serviceViaListener{
		wgInterface: wgIface,
		dnsMux:      mux,
		customAddr:  customAddr,
		firewall:    fw,
		server: &dns.Server{
			Net:     "udp",
			Handler: mux,
			UDPSize: 65535,
		},
		tcpServer: &dns.Server{
			Net:     "tcp",
			Handler: mux,
		},
	}

	return s
}

func (s *serviceViaListener) Listen() error {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	if s.listenerIsRunning {
		return nil
	}

	var err error
	s.listenIP, s.listenPort, err = s.evalListenAddress()
	if err != nil {
		log.Errorf("failed to eval runtime address: %s", err)
		return fmt.Errorf("eval listen address: %w", err)
	}
	s.listenIP = s.listenIP.Unmap()
	addr := net.JoinHostPort(s.listenIP.String(), strconv.Itoa(int(s.listenPort)))
	s.server.Addr = addr
	s.tcpServer.Addr = addr

	log.Debugf("starting dns on %s (UDP + TCP)", addr)
	s.listenerIsRunning = true

	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			log.Errorf("failed to run DNS UDP server on port %d: %v", s.listenPort, err)
		}

		s.listenerFlagLock.Lock()
		unexpected := s.listenerIsRunning
		s.listenerIsRunning = false
		s.listenerFlagLock.Unlock()

		if unexpected {
			if err := s.tcpServer.Shutdown(); err != nil {
				log.Debugf("failed to shutdown DNS TCP server: %v", err)
			}
		}
	}()

	go func() {
		if err := s.tcpServer.ListenAndServe(); err != nil {
			log.Errorf("failed to run DNS TCP server on port %d: %v", s.listenPort, err)
		}
	}()

	if s.listenPort != DefaultPort {
		s.setupDNAT()
	}

	return nil
}

// setupDNAT redirects port 53 to the port the DNS server actually listens on.
// Both protocols must be redirected or none: RuntimePort reports port 53 only
// while the full redirect is in place, so a half-configured redirect would
// advertise a resolver that answers over one protocol.
func (s *serviceViaListener) setupDNAT() {
	if s.firewall == nil {
		log.Errorf("no firewall manager available to redirect DNS port %d to %d, "+
			"clients pointed at %s will not reach the resolver", DefaultPort, s.listenPort, s.listenIP)
		return
	}

	// Clear whatever an earlier removal left behind first. Those rules can point
	// at an address or port this listener no longer uses, and they are matched
	// before anything added now, so adding a redirect on top of one would keep
	// sending port 53 traffic to the previous listener while reporting the
	// redirect as complete. The rules stay recorded for a later attempt.
	if err := s.removeDNAT(); err != nil {
		log.Errorf("failed to remove stale DNS DNAT rules, leaving port %d redirected to the previous listener: %v",
			DefaultPort, err)
		return
	}

	for _, proto := range dnatProtocols {
		if err := s.firewall.AddOutputDNAT(s.listenIP, proto, DefaultPort, s.listenPort); err != nil {
			log.Errorf("failed to add DNS %s DNAT rule, DNS on port %d will not work: %v",
				proto, DefaultPort, err)
			if err := s.removeDNAT(); err != nil {
				log.Warnf("failed to roll back DNS DNAT rules, retrying on stop: %v", err)
			}
			return
		}
		s.dnatRules = append(s.dnatRules, dnatRule{protocol: proto, ip: s.listenIP, port: s.listenPort})
	}

	log.Infof("added DNS DNAT rules: %s:%d -> %s:%d (UDP + TCP)", s.listenIP, DefaultPort, s.listenIP, s.listenPort)
}

// removeDNAT removes every installed port 53 redirect. A rule whose removal
// fails stays recorded so a later setup or Stop retries it, rather than leaving
// port 53 pointing at a resolver that is no longer listening.
func (s *serviceViaListener) removeDNAT() error {
	if s.firewall == nil {
		return nil
	}

	var merr *multierror.Error
	var remaining []dnatRule
	for _, rule := range s.dnatRules {
		if err := s.firewall.RemoveOutputDNAT(rule.ip, rule.protocol, DefaultPort, rule.port); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove DNS %s DNAT rule for %s:%d: %w",
				rule.protocol, rule.ip, rule.port, err))
			remaining = append(remaining, rule)
		}
	}
	s.dnatRules = remaining

	return nberrors.FormatErrorOrNil(merr)
}

func (s *serviceViaListener) Stop() error {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	var merr *multierror.Error

	// Redirects are removed even when the listener is already stopped, so that
	// a removal which failed earlier is retried instead of leaving port 53
	// pointing at a resolver that no longer listens.
	if err := s.removeDNAT(); err != nil {
		merr = multierror.Append(merr, err)
	}

	if !s.listenerIsRunning {
		return nberrors.FormatErrorOrNil(merr)
	}
	s.listenerIsRunning = false

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.ShutdownContext(ctx); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("stop DNS UDP server: %w", err))
	}

	if err := s.tcpServer.ShutdownContext(ctx); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("stop DNS TCP server: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (s *serviceViaListener) RegisterMux(pattern string, handler dns.Handler) {
	log.Debugf("registering dns handler for pattern: %s", pattern)
	s.dnsMux.Handle(pattern, handler)
}

func (s *serviceViaListener) DeregisterMux(pattern string) {
	s.dnsMux.HandleRemove(pattern)
}

func (s *serviceViaListener) RuntimePort() int {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	if s.redirectInstalled() {
		return DefaultPort
	}
	return int(s.listenPort)
}

// redirectInstalled reports whether every protocol is redirected from port 53
// to the address and port the listener currently serves. Rules left over from
// an earlier listener do not count.
func (s *serviceViaListener) redirectInstalled() bool {
	for _, proto := range dnatProtocols {
		current := dnatRule{protocol: proto, ip: s.listenIP, port: s.listenPort}
		if !slices.Contains(s.dnatRules, current) {
			return false
		}
	}
	return true
}

func (s *serviceViaListener) RuntimeIP() netip.Addr {
	return s.listenIP
}

// evalListenAddress figures out the listen address for the DNS server.
// IPv4-only: all peers have a v4 overlay address, and DNS config points to v4.
// Prefers port 53 on the overlay interface or lo, so no redirect is needed at
// all; when it is taken it falls back to port 5053 and then to a random free
// port, both of which need the port 53 redirect set up by setupDNAT.
func (s *serviceViaListener) evalListenAddress() (netip.Addr, uint16, error) {
	if s.customAddr != nil {
		return s.customAddr.Addr(), s.customAddr.Port(), nil
	}

	if ip, ok := s.testFreePort(DefaultPort); ok {
		return ip, DefaultPort, nil
	}

	if ip, ok := s.testFreePort(customPort); ok {
		return ip, customPort, nil
	}

	ip := s.wgInterface.Address().IP
	port, err := s.randomFreePort(ip)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("find a free port for DNS server: %w", err)
	}

	return ip, port, nil
}

func (s *serviceViaListener) testFreePort(port int) (netip.Addr, bool) {
	var ips []netip.Addr
	if runtime.GOOS != "darwin" {
		ips = []netip.Addr{s.wgInterface.Address().IP, defaultIP, customIP}
	} else {
		ips = []netip.Addr{defaultIP, customIP}
	}

	for _, ip := range ips {
		if !s.tryToBind(ip, port) {
			continue
		}

		return ip, true
	}
	return netip.Addr{}, false
}

func (s *serviceViaListener) tryToBind(ip netip.Addr, port int) bool {
	addrPort := netip.AddrPortFrom(ip, uint16(port))

	udpAddr := net.UDPAddrFromAddrPort(addrPort)
	udpLn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Warnf("binding dns UDP on %s is not available: %s", addrPort, err)
		return false
	}
	if err := udpLn.Close(); err != nil {
		log.Debugf("close UDP probe listener: %s", err)
	}

	tcpAddr := net.TCPAddrFromAddrPort(addrPort)
	tcpLn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Warnf("binding dns TCP on %s is not available: %s", addrPort, err)
		return false
	}
	if err := tcpLn.Close(); err != nil {
		log.Debugf("close TCP probe listener: %s", err)
	}

	return true
}

// randomFreePort returns a port that is free on ip for both UDP and TCP, since
// the DNS server binds both. The probe listeners are closed again, so the port
// is only likely, not guaranteed, to still be free when the server binds it.
func (s *serviceViaListener) randomFreePort(ip netip.Addr) (uint16, error) {
	for range randomPortAttempts {
		probeListener, err := net.ListenUDP("udp4", &net.UDPAddr{})
		if err != nil {
			return 0, fmt.Errorf("bind random port: %w", err)
		}

		port := uint16(probeListener.LocalAddr().(*net.UDPAddr).Port)
		if err := probeListener.Close(); err != nil {
			return 0, fmt.Errorf("free up probed port: %w", err)
		}

		if s.tryToBind(ip, int(port)) {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no port free for UDP and TCP on %s after %d attempts", ip, randomPortAttempts)
}
