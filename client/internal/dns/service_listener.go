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
)

const (
	customPort = 5053
	defaultIP  = "127.0.0.1"
	customIP   = "127.0.0.153"
)

type serviceViaListener struct {
	wgInterface WGIface

	dnsMux            *dns.ServeMux
	server            *dns.Server
	runtimeIP         string
	runtimePort       int
	listenerIsRunning bool
	listenerFlagLock  sync.Mutex
}

func newServiceViaListener(wgIface WGIface, customAddr *netip.AddrPort) *serviceViaListener {
	mux := dns.NewServeMux()

	s := &serviceViaListener{
		wgInterface: wgIface,
		dnsMux:      mux,
	}
	// todo: run eval after WGIface creation
	s.runtimeIP, s.runtimePort = s.evalRuntimeAddress(customAddr)
	s.server = &dns.Server{
		Net:     "udp",
		Handler: mux,
		Addr:    fmt.Sprintf("%s:%d", s.runtimeIP, s.runtimePort),
		UDPSize: 65535,
	}
	return s
}

func (s *serviceViaListener) Listen() {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	if s.listenerIsRunning {
		return
	}

	log.Debugf("starting dns on %s", s.server.Addr)
	go func() {
		s.setListenerStatus(true)
		defer s.setListenerStatus(false)

		err := s.server.ListenAndServe()
		if err != nil {
			log.Errorf("dns server running with %d port returned an error: %v. Will not retry", s.runtimePort, err)
		}
	}()
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
}

func (s *serviceViaListener) RegisterMux(pattern string, handler dns.Handler) {
	s.dnsMux.Handle(pattern, handler)
}

func (s *serviceViaListener) DeregisterMux(pattern string) {
	s.dnsMux.HandleRemove(pattern)
}

func (s *serviceViaListener) RuntimePort() int {
	return s.runtimePort
}

func (s *serviceViaListener) RuntimeIP() string {
	return s.runtimeIP
}

func (s *serviceViaListener) setListenerStatus(running bool) {
	s.listenerIsRunning = running
}

func (s *serviceViaListener) getFirstListenerAvailable() (string, int, error) {
	ips := []string{defaultIP, customIP}
	if runtime.GOOS != "darwin" {
		ips = append([]string{s.wgInterface.Address().IP.String()}, ips...)
	}
	ports := []int{defaultPort, customPort}
	for _, port := range ports {
		for _, ip := range ips {
			addrString := fmt.Sprintf("%s:%d", ip, port)
			udpAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addrString))
			probeListener, err := net.ListenUDP("udp", udpAddr)
			if err == nil {
				err = probeListener.Close()
				if err != nil {
					log.Errorf("got an error closing the probe listener, error: %s", err)
				}
				return ip, port, nil
			}
			log.Warnf("binding dns on %s is not available, error: %s", addrString, err)
		}
	}
	return "", 0, fmt.Errorf("unable to find an unused ip and port combination. IPs tested: %v and ports %v", ips, ports)
}

func (s *serviceViaListener) evalRuntimeAddress(customAddress *netip.AddrPort) (string, int) {
	if customAddress != nil {
		return customAddress.Addr().String(), int(customAddress.Port())
	}

	ip, port, err := s.getFirstListenerAvailable()
	if err != nil {
		// todo error handling
		log.Error(err)
	}
	return ip, port
}
