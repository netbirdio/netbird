package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/ebpf"
	ebpfMgr "github.com/netbirdio/netbird/client/internal/ebpf/manager"
)

const (
	customPort = 5053
	defaultIP  = "127.0.0.1"
	customIP   = "127.0.0.153"
)

type serviceViaListener struct {
	wgInterface      WGIface
	dnsMux           *dns.ServeMux
	customAddr       *netip.AddrPort
	server           *dns.Server
	tcpServer        *dns.Server
	listenIP         string
	listenPort       uint16
	listenerCount    int
	listenerFlagLock sync.Mutex
	ebpfService      ebpfMgr.Manager
}

func newServiceViaListener(wgIface WGIface, customAddr *netip.AddrPort) *serviceViaListener {
	mux := dns.NewServeMux()

	s := &serviceViaListener{
		wgInterface: wgIface,
		dnsMux:      mux,
		customAddr:  customAddr,
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

// Listen starts both UDP and TCP DNS listeners concurrently.
func (s *serviceViaListener) Listen() error {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	if s.listenerCount > 0 {
		return nil
	}

	ip, port, err := s.evalListenAddress()
	if err != nil {
		log.Errorf("failed to eval runtime address: %s", err)
		return fmt.Errorf("eval listen address: %w", err)
	}
	s.listenIP = ip
	s.listenPort = port

	addr := fmt.Sprintf("%s:%d", ip, port)
	s.server.Addr = addr
	s.tcpServer.Addr = addr

	// mark two listeners as active
	s.listenerCount = 2

	log.Tracef("starting DNS servers on %s (udp & tcp)", addr)
	go s.serve(s.server)
	go s.serve(s.tcpServer)

	return nil
}

// serve runs a dns.Server and updates listener count on exit
func (s *serviceViaListener) serve(srv *dns.Server) {
	defer s.setListenerStatus(false)
	if err := srv.ListenAndServe(); err != nil {
		log.Errorf("%s server on %s returned an error: %v", srv.Net, srv.Addr, err)
	}
}

// Stop gracefully shuts down both UDP and TCP listeners
func (s *serviceViaListener) Stop() {
	s.listenerFlagLock.Lock()
	if s.listenerCount == 0 {
		s.listenerFlagLock.Unlock()
		return
	}
	s.listenerFlagLock.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.ShutdownContext(ctx); err != nil {
		log.Errorf("stopping UDP DNS server returned an error: %v", err)
	}
	if err := s.tcpServer.ShutdownContext(ctx); err != nil {
		log.Errorf("stopping TCP DNS server returned an error: %v", err)
	}

	if s.ebpfService != nil {
		if err := s.ebpfService.FreeDNSFwd(); err != nil {
			log.Errorf("stopping traffic forwarder returned an error: %v", err)
		}
	}
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
		return defaultPort
	}
	return int(s.listenPort)
}

func (s *serviceViaListener) RuntimeIP() string {
	return s.listenIP
}

func (s *serviceViaListener) setListenerStatus(running bool) {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()
	if running {
		s.listenerCount++
	} else {
		s.listenerCount--
		if s.listenerCount < 0 {
			s.listenerCount = 0
		}
	}
}

// evalListenAddress figure out the listen address for the DNS server
// first check the 53 port availability on WG interface or lo, if not success
// pick a random port on WG interface for eBPF, if not success
// check the 5053 port availability on WG interface or lo without eBPF usage,
func (s *serviceViaListener) evalListenAddress() (string, uint16, error) {
	if s.customAddr != nil {
		return s.customAddr.Addr().String(), s.customAddr.Port(), nil
	}

	ip, ok := s.testFreePort(defaultPort)
	if ok {
		return ip, defaultPort, nil
	}

	ebpfSrv, port, ok := s.tryToUseeBPF()
	if ok {
		s.ebpfService = ebpfSrv
		return s.wgInterface.Address().IP.String(), port, nil
	}

	ip, ok = s.testFreePort(customPort)
	if ok {
		return ip, customPort, nil
	}

	return "", 0, fmt.Errorf("failed to find a free port for DNS server")
}

func (s *serviceViaListener) testFreePort(port int) (string, bool) {
	var ips []string
	if runtime.GOOS != "darwin" {
		ips = []string{s.wgInterface.Address().IP.String(), defaultIP, customIP}
	} else {
		ips = []string{defaultIP, customIP}
	}

	for _, ip := range ips {
		if !s.tryToBind(ip, port) {
			continue
		}

		return ip, true
	}
	return "", false
}

func (s *serviceViaListener) tryToBind(ip string, port int) bool {
	addrString := fmt.Sprintf("%s:%d", ip, port)
	udpAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addrString))
	probeListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Warnf("binding dns on %s is not available, error: %s", addrString, err)
		return false
	}

	err = probeListener.Close()
	if err != nil {
		log.Errorf("got an error closing the probe listener, error: %s", err)
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
	ok := s.tryToBind(s.wgInterface.Address().IP.String(), customPort)
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
