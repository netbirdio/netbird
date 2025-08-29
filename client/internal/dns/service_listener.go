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
	listenIP          netip.Addr
	listenPort        uint16
	listenerIsRunning bool
	listenerFlagLock  sync.Mutex
	ebpfService       ebpfMgr.Manager
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
	s.server.Addr = fmt.Sprintf("%s:%d", s.listenIP, s.listenPort)
	log.Debugf("starting dns on %s", s.server.Addr)
	go func() {
		s.setListenerStatus(true)
		defer s.setListenerStatus(false)

		err := s.server.ListenAndServe()
		if err != nil {
			log.Errorf("dns server running with %d port returned an error: %v. Will not retry", s.listenPort, err)
		}
	}()

	return nil
}

func (s *serviceViaListener) Stop() {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	if !s.listenerIsRunning {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.server.ShutdownContext(ctx)
	if err != nil {
		log.Errorf("stopping dns server listener returned an error: %v", err)
	}

	if s.ebpfService != nil {
		err = s.ebpfService.FreeDNSFwd()
		if err != nil {
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
		return DefaultPort
	} else {
		return int(s.listenPort)
	}
}

func (s *serviceViaListener) RuntimeIP() netip.Addr {
	return s.listenIP
}

func (s *serviceViaListener) setListenerStatus(running bool) {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	s.listenerIsRunning = running
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
