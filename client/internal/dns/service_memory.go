package dns

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/client/net"
)

type ServiceViaMemory struct {
	wgInterface       WGIface
	dnsMux            *dns.ServeMux
	runtimeIP         netip.Addr
	runtimePort       int
	udpFilterHookID   string
	listenerIsRunning bool
	listenerFlagLock  sync.Mutex
}

func NewServiceViaMemory(wgIface WGIface) *ServiceViaMemory {
	lastIP, err := nbnet.GetLastIPFromNetwork(wgIface.Address().Network, 1)
	if err != nil {
		log.Errorf("get last ip from network: %v", err)
	}
	s := &ServiceViaMemory{
		wgInterface: wgIface,
		dnsMux:      dns.NewServeMux(),

		runtimeIP:   lastIP,
		runtimePort: defaultPort,
	}
	return s
}

func (s *ServiceViaMemory) Listen() error {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	if s.listenerIsRunning {
		return nil
	}

	var err error
	s.udpFilterHookID, err = s.filterDNSTraffic()
	if err != nil {
		return fmt.Errorf("filter dns traffice: %w", err)
	}
	s.listenerIsRunning = true

	log.Debugf("dns service listening on: %s", s.RuntimeIP())
	return nil
}

func (s *ServiceViaMemory) Stop() {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	if !s.listenerIsRunning {
		return
	}

	if err := s.wgInterface.GetFilter().RemovePacketHook(s.udpFilterHookID); err != nil {
		log.Errorf("unable to remove DNS packet hook: %s", err)
	}

	s.listenerIsRunning = false
}

func (s *ServiceViaMemory) RegisterMux(pattern string, handler dns.Handler) {
	s.dnsMux.Handle(pattern, handler)
}

func (s *ServiceViaMemory) DeregisterMux(pattern string) {
	s.dnsMux.HandleRemove(pattern)
}

func (s *ServiceViaMemory) RuntimePort() int {
	return s.runtimePort
}

func (s *ServiceViaMemory) RuntimeIP() netip.Addr {
	return s.runtimeIP
}

func (s *ServiceViaMemory) filterDNSTraffic() (string, error) {
	filter := s.wgInterface.GetFilter()
	if filter == nil {
		return "", fmt.Errorf("can't set DNS filter, filter not initialized")
	}

	firstLayerDecoder := layers.LayerTypeIPv4
	if s.wgInterface.Address().IP.Is6() {
		firstLayerDecoder = layers.LayerTypeIPv6
	}

	hook := func(packetData []byte) bool {
		// Decode the packet
		packet := gopacket.NewPacket(packetData, firstLayerDecoder, gopacket.Default)

		// Get the UDP layer
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		udp := udpLayer.(*layers.UDP)

		msg := new(dns.Msg)
		if err := msg.Unpack(udp.Payload); err != nil {
			log.Tracef("parse DNS request: %v", err)
			return true
		}

		writer := responseWriter{
			packet: packet,
			device: s.wgInterface.GetDevice().Device,
		}
		go s.dnsMux.ServeDNS(&writer, msg)
		return true
	}

	return filter.AddUDPPacketHook(false, s.runtimeIP, uint16(s.runtimePort), hook), nil
}
