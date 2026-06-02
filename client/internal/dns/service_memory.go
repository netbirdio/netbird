package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
	nbnet "github.com/netbirdio/netbird/client/net"
)

type ServiceViaMemory struct {
	wgInterface       WGIface
	dnsMux            *dns.ServeMux
	runtimeIP         netip.Addr
	runtimePort       int
	tcpDNS            *tcpDNSServer
	tcpHookSet        bool
	listenerIsRunning bool
	listenerFlagLock  sync.Mutex
}

func NewServiceViaMemory(wgIface WGIface) *ServiceViaMemory {
	lastIP, err := nbnet.GetLastIPFromNetwork(wgIface.Address().Network, 1)
	if err != nil {
		log.Errorf("get last ip from network: %v", err)
	}

	return &ServiceViaMemory{
		wgInterface: wgIface,
		dnsMux:      dns.NewServeMux(),
		runtimeIP:   lastIP,
		runtimePort: DefaultPort,
	}
}

func (s *ServiceViaMemory) Listen() error {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	if s.listenerIsRunning {
		return nil
	}

	if err := s.filterDNSTraffic(); err != nil {
		return fmt.Errorf("filter dns traffic: %w", err)
	}
	s.listenerIsRunning = true

	log.Debugf("dns service listening on: %s", s.RuntimeIP())
	return nil
}

func (s *ServiceViaMemory) Stop() error {
	s.listenerFlagLock.Lock()
	defer s.listenerFlagLock.Unlock()

	if !s.listenerIsRunning {
		return nil
	}

	filter := s.wgInterface.GetFilter()
	if filter != nil {
		filter.SetUDPPacketHook(s.runtimeIP, uint16(s.runtimePort), nil)
		if s.tcpHookSet {
			filter.SetTCPPacketHook(s.runtimeIP, uint16(s.runtimePort), nil)
		}
	}

	if s.tcpDNS != nil {
		s.tcpDNS.Stop()
	}

	s.listenerIsRunning = false

	return nil
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

func (s *ServiceViaMemory) filterDNSTraffic() error {
	filter := s.wgInterface.GetFilter()
	if filter == nil {
		return errors.New("DNS filter not initialized")
	}

	// Create TCP DNS server lazily here since the device may not exist at construction time.
	if s.tcpDNS == nil {
		if dev := s.wgInterface.GetDevice(); dev != nil {
			// MTU only affects TCP segment sizing; DNS messages are small so this has no practical impact.
			s.tcpDNS = newTCPDNSServer(s.dnsMux, dev.Device, s.runtimeIP, uint16(s.runtimePort), iface.DefaultMTU)
		}
	}

	firstLayerDecoder := layers.LayerTypeIPv4
	if s.wgInterface.Address().IP.Is6() {
		firstLayerDecoder = layers.LayerTypeIPv6
	}

	hook := func(packetData []byte) bool {
		packet := gopacket.NewPacket(packetData, firstLayerDecoder, gopacket.Default)

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return true
		}
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return true
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(udp.Payload); err != nil {
			log.Tracef("parse DNS request: %v", err)
			return true
		}

		dev := s.wgInterface.GetDevice()
		if dev == nil {
			return true
		}

		writer := &responseWriter{
			remote: remoteAddrFromPacket(packet),
			packet: packet,
			device: dev.Device,
		}
		go s.dnsMux.ServeDNS(writer, msg)
		return true
	}

	filter.SetUDPPacketHook(s.runtimeIP, uint16(s.runtimePort), hook)

	if s.tcpDNS != nil {
		tcpHook := func(packetData []byte) bool {
			s.tcpDNS.InjectPacket(packetData)
			return true
		}
		filter.SetTCPPacketHook(s.runtimeIP, uint16(s.runtimePort), tcpHook)
		s.tcpHookSet = true
	}

	return nil
}
