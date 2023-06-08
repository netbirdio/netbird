package dns

import (
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/iface/mocks"
)

func TestResponseWriterLocalAddr(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	device := mocks.NewMockDevice(ctrl)
	device.EXPECT().Write(gomock.Any(), gomock.Any())

	request := &dns.Msg{
		Question: []dns.Question{{
			Name:   "google.com.",
			Qtype:  dns.TypeA,
			Qclass: dns.TypeA,
		}},
	}

	replyMessage := &dns.Msg{}
	replyMessage.SetReply(request)
	replyMessage.RecursionAvailable = true
	replyMessage.Rcode = dns.RcodeSuccess
	replyMessage.Answer = []dns.RR{
		&dns.A{
			A: net.IPv4(8, 8, 8, 8),
		},
	}

	ipv4 := &layers.IPv4{
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(127, 0, 0, 1),
		DstIP:    net.IPv4(127, 0, 0, 2),
	}
	udp := &layers.UDP{
		DstPort: 53,
		SrcPort: 45223,
	}
	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Error("failed to set network layer for checksum")
		return
	}

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	requestData, err := request.Pack()
	if err != nil {
		t.Errorf("got an error while packing the request message, error: %v", err)
		return
	}
	payload := gopacket.Payload(requestData)

	if err := gopacket.SerializeLayers(buffer, options, ipv4, udp, payload); err != nil {
		t.Errorf("failed to serialize packet: %v", err)
		return
	}

	rw := &responseWriter{
		local: &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 55223,
		},
		remote: &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 53,
		},
		packet: gopacket.NewPacket(
			buffer.Bytes(),
			layers.LayerTypeIPv4,
			gopacket.Default,
		),
		device: device,
	}
	if err := rw.WriteMsg(replyMessage); err != nil {
		t.Errorf("got an error while writing the local resolver response, error: %v", err)
		return
	}
}
