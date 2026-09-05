package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
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
)

var (
	defaultIP = netip.MustParseAddr("127.0.0.1")
	customIP  = netip.MustParseAddr("127.0.0.153")
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
	dnatConfigured    bool
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
// Both protocols must be redirected or none: RuntimePort reports port 53 while
// the redirect is in place, so a half-configured redirect would advertise a
// resolver that only answers over one protocol.
func (s *serviceViaListener) setupDNAT() {
	if s.firewall == nil {
		log.Errorf("no firewall manager available to redirect DNS port %d to %d, "+
			"clients pointed at %s will not reach the resolver", DefaultPort, s.listenPort, s.listenIP)
		return
	}

	protocols := []firewall.Protocol{firewall.ProtocolUDP, firewall.ProtocolTCP}
	for i, proto := range protocols {
		if err := s.firewall.AddOutputDNAT(s.listenIP, proto, DefaultPort, s.listenPort); err != nil {
			log.Errorf("failed to add DNS %s DNAT rule, DNS on port %d will not work: %v",
				proto, DefaultPort, err)
			if err := s.removeDNAT(protocols[:i]); err != nil {
				log.Warnf("failed to roll back DNS DNAT rules: %v", err)
			}
			return
		}
	}

	s.dnatConfigured = true
	log.Infof("added DNS DNAT rules: %s:%d -> %s:%d (UDP + TCP)", s.listenIP, DefaultPort, s.listenIP, s.listenPort)
}

func (s *serviceViaListener) removeDNAT(protocols []firewall.Protocol) error {
	var merr *multierror.Error
	for _, proto := range protocols {
		if err := s.firewall.RemoveOutputDNAT(s.listenIP, proto, DefaultPort, s.listenPort); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove DNS %s DNAT rule: %w", proto, err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (s *serviceViaListener) Stop() error {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	if !s.listenerIsRunning {
		return nil
	}
	s.listenerIsRunning = false

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var merr *multierror.Error

	if err := s.server.ShutdownContext(ctx); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("stop DNS UDP server: %w", err))
	}

	if err := s.tcpServer.ShutdownContext(ctx); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("stop DNS TCP server: %w", err))
	}

	if s.dnatConfigured {
		if err := s.removeDNAT([]firewall.Protocol{firewall.ProtocolUDP, firewall.ProtocolTCP}); err != nil {
			merr = multierror.Append(merr, err)
		}
		s.dnatConfigured = false
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

	if s.dnatConfigured {
		return DefaultPort
	}
	return int(s.listenPort)
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

	port, err := randomFreePort()
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("find a free port for DNS server: %w", err)
	}

	return s.wgInterface.Address().IP, port, nil
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

// randomFreePort returns a port the kernel reports as free. The probe listener
// is closed again, so the port is only likely, not guaranteed, to still be free
// when the DNS server binds it.
func randomFreePort() (uint16, error) {
	probeListener, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return 0, fmt.Errorf("bind random port: %w", err)
	}

	port := uint16(probeListener.LocalAddr().(*net.UDPAddr).Port)
	if err := probeListener.Close(); err != nil {
		return 0, fmt.Errorf("free up probed port: %w", err)
	}

	return port, nil
}
