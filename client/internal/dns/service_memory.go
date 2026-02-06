package dns

import (
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
	udpFilterHookID   string
	tcpFilterHookID   string
	tcpDNS            *tcpDNSServer
	listenerIsRunning bool
	listenerFlagLock  sync.Mutex
}

func NewServiceViaMemory(wgIface WGIface) *ServiceViaMemory {
	lastIP, err := nbnet.GetLastIPFromNetwork(wgIface.Address().Network, 1)
	if err != nil {
		log.Errorf("get last ip from network: %v", err)
	}

	mux := dns.NewServeMux()

	return &ServiceViaMemory{
		wgInterface: wgIface,
		dnsMux:      mux,
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

	filter := s.wgInterface.GetFilter()
	if err := filter.RemovePacketHook(s.udpFilterHookID); err != nil {
		log.Errorf("remove DNS UDP packet hook: %s", err)
	}

	if s.tcpFilterHookID != "" {
		if err := filter.RemovePacketHook(s.tcpFilterHookID); err != nil {
			log.Errorf("remove DNS TCP packet hook: %s", err)
		}
	}

	if s.tcpDNS != nil {
		s.tcpDNS.Stop()
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
		udp := udpLayer.(*layers.UDP)

		msg := new(dns.Msg)
		if err := msg.Unpack(udp.Payload); err != nil {
			log.Tracef("parse DNS request: %v", err)
			return true
		}

		writer := &truncationAwareWriter{
			responseWriter: responseWriter{
				packet: packet,
				device: s.wgInterface.GetDevice().Device,
			},
			tcpDNS: s.tcpDNS,
		}
		go s.dnsMux.ServeDNS(writer, msg)
		return true
	}

	udpHookID := filter.AddUDPPacketHook(false, s.runtimeIP, uint16(s.runtimePort), hook)

	if s.tcpDNS != nil {
		tcpHook := func(packetData []byte) bool {
			s.tcpDNS.EnsureRunning()
			s.tcpDNS.InjectPacket(packetData)
			return true
		}
		s.tcpFilterHookID = filter.AddTCPPacketHook(false, s.runtimeIP, uint16(s.runtimePort), tcpHook)
	}

	return udpHookID, nil
}
