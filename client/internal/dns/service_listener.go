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
	"github.com/netbirdio/netbird/client/internal/ebpf"
	ebpfMgr "github.com/netbirdio/netbird/client/internal/ebpf/manager"
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
	ebpfService       ebpfMgr.Manager
	firewall          Firewall
	tcpDNATConfigured bool
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

	// When eBPF redirects UDP port 53 to our listen port, TCP still needs
	// a DNAT rule because eBPF only handles UDP.
	if s.ebpfService != nil && s.firewall != nil && s.listenPort != DefaultPort {
		if err := s.firewall.AddOutputDNAT(s.listenIP, firewall.ProtocolTCP, DefaultPort, s.listenPort); err != nil {
			log.Warnf("failed to add DNS TCP DNAT rule, TCP DNS on port 53 will not work: %v", err)
		} else {
			s.tcpDNATConfigured = true
			log.Infof("added DNS TCP DNAT rule: %s:%d -> %s:%d", s.listenIP, DefaultPort, s.listenIP, s.listenPort)
		}
	}

	return nil
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

	if s.tcpDNATConfigured && s.firewall != nil {
		if err := s.firewall.RemoveOutputDNAT(s.listenIP, firewall.ProtocolTCP, DefaultPort, s.listenPort); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove DNS TCP DNAT rule: %w", err))
		}
		s.tcpDNATConfigured = false
	}

	if s.ebpfService != nil {
		if err := s.ebpfService.FreeDNSFwd(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("stop traffic forwarder: %w", err))
		}
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

	if s.ebpfService != nil {
		return DefaultPort
	} else {
		return int(s.listenPort)
	}
}

func (s *serviceViaListener) RuntimeIP() netip.Addr {
	return s.listenIP
}


// evalListenAddress figure out the listen address for the DNS server
// first check the 53 port availability on WG interface or lo, if not success
// pick a random port on WG interface for eBPF, if not success
// check the 5053 port availability on WG interface or lo without eBPF usage,
func (s *serviceViaListener) evalListenAddress() (netip.Addr, uint16, error) {
	if s.customAddr != nil {
		return s.customAddr.Addr(), s.customAddr.Port(), nil
	}

	ip, ok := s.testFreePort(DefaultPort)
	if ok {
		return ip, DefaultPort, nil
	}

	ebpfSrv, port, ok := s.tryToUseeBPF()
	if ok {
		s.ebpfService = ebpfSrv
		return s.wgInterface.Address().IP, port, nil
	}

	ip, ok = s.testFreePort(customPort)
	if ok {
		return ip, customPort, nil
	}

	return netip.Addr{}, 0, fmt.Errorf("failed to find a free port for DNS server")
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

// tryToUseeBPF decides whether to apply eBPF program to capture DNS traffic on port 53.
// This is needed because on some operating systems if we start a DNS server not on a default port 53,
// the domain name  resolution won't work. So, in case we are running on Linux and picked a free
// port we should fall back to the eBPF solution that will capture traffic on port 53 and forward
// it to a local DNS server running on the chosen port.
func (s *serviceViaListener) tryToUseeBPF() (ebpfMgr.Manager, uint16, bool) {
	if runtime.GOOS != "linux" {
		return nil, 0, false
	}

	port, err := s.generateFreePort() //nolint:staticcheck,unused
	if err != nil {
		log.Warnf("failed to generate a free port for eBPF DNS forwarder server: %s", err)
		return nil, 0, false
	}

	ebpfSrv := ebpf.GetEbpfManagerInstance()
	err = ebpfSrv.LoadDNSFwd(s.wgInterface.Address().IP.String(), int(port))
	if err != nil {
		log.Warnf("failed to load DNS forwarder eBPF program, error: %s", err)
		return nil, 0, false
	}

	return ebpfSrv, port, true
}

func (s *serviceViaListener) generateFreePort() (uint16, error) {
	ok := s.tryToBind(s.wgInterface.Address().IP, customPort)
	if ok {
		return customPort, nil
	}

	udpAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("0.0.0.0:0"))
	probeListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Debugf("failed to bind random port for DNS: %s", err)
		return 0, err
	}

	addrPort := netip.MustParseAddrPort(probeListener.LocalAddr().String()) // might panic if address is incorrect
	err = probeListener.Close()
	if err != nil {
		log.Debugf("failed to free up DNS port: %s", err)
		return 0, err
	}
	return addrPort.Port(), nil
}
