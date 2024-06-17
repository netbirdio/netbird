package dns

import (
	"fmt"
	"math/big"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type serviceViaMemory struct {
	wgInterface       WGIface
	dnsMux            *dns.ServeMux
	runtimeIP         string
	runtimePort       int
	udpFilterHookID   string
	listenerIsRunning bool
	listenerFlagLock  sync.Mutex
}

func newServiceViaMemory(wgIface WGIface) *serviceViaMemory {
	s := &serviceViaMemory{
		wgInterface: wgIface,
		dnsMux:      dns.NewServeMux(),

		runtimeIP:   getLastIPFromNetwork(wgIface.Address().Network, 1),
		runtimePort: defaultPort,
	}
	return s
}

func (s *serviceViaMemory) Listen() error {
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

func (s *serviceViaMemory) Stop() {
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

func (s *serviceViaMemory) RegisterMux(pattern string, handler dns.Handler) {
	s.dnsMux.Handle(pattern, handler)
}

func (s *serviceViaMemory) DeregisterMux(pattern string) {
	s.dnsMux.HandleRemove(pattern)
}

func (s *serviceViaMemory) RuntimePort() int {
	return s.runtimePort
}

func (s *serviceViaMemory) RuntimeIP() string {
	return s.runtimeIP
}

func (s *serviceViaMemory) filterDNSTraffic() (string, error) {
	filter := s.wgInterface.GetFilter()
	if filter == nil {
		return "", fmt.Errorf("can't set DNS filter, filter not initialized")
	}

	firstLayerDecoder := layers.LayerTypeIPv4
	if s.wgInterface.Address().Network.IP.To4() == nil {
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

	return filter.AddUDPPacketHook(false, net.ParseIP(s.runtimeIP), uint16(s.runtimePort), hook), nil
}

func getLastIPFromNetwork(network *net.IPNet, fromEnd int) string {
	// Calculate the last IP in the CIDR range
	var endIP net.IP
	for i := 0; i < len(network.IP); i++ {
		endIP = append(endIP, network.IP[i]|^network.Mask[i])
	}

	// convert to big.Int
	endInt := big.NewInt(0)
	endInt.SetBytes(endIP)

	// subtract fromEnd from the last ip
	fromEndBig := big.NewInt(int64(fromEnd))
	resultInt := big.NewInt(0)
	resultInt.Sub(endInt, fromEndBig)

	return net.IP(resultInt.Bytes()).String()
}
