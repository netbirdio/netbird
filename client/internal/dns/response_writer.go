package dns

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/tun"
)

type responseWriter struct {
	local  net.Addr
	remote net.Addr
	packet gopacket.Packet
	device tun.Device
}

// LocalAddr returns the net.Addr of the server
func (r *responseWriter) LocalAddr() net.Addr {
	return r.local
}

// RemoteAddr returns the net.Addr of the client that sent the current request.
func (r *responseWriter) RemoteAddr() net.Addr {
	return r.remote
}

// WriteMsg writes a reply back to the client.
func (r *responseWriter) WriteMsg(msg *dns.Msg) error {
	buff, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("pack: %w", err)
	}

	if _, err := r.Write(buff); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// Write writes a raw buffer back to the client.
func (r *responseWriter) Write(data []byte) (int, error) {
	var ip gopacket.SerializableLayer

	// Get the UDP layer
	udpLayer := r.packet.Layer(layers.LayerTypeUDP)
	udp := udpLayer.(*layers.UDP)

	// Swap the source and destination addresses for the response
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort

	// Check if it's an IPv4 packet
	if ipv4Layer := r.packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		ipv4.SrcIP, ipv4.DstIP = ipv4.DstIP, ipv4.SrcIP
		ip = ipv4
	} else if ipv6Layer := r.packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		ipv6.SrcIP, ipv6.DstIP = ipv6.DstIP, ipv6.SrcIP
		ip = ipv6
	}

	if err := udp.SetNetworkLayerForChecksum(ip.(gopacket.NetworkLayer)); err != nil {
		return 0, fmt.Errorf("failed to set network layer for checksum: %v", err)
	}

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	payload := gopacket.Payload(data)
	err := gopacket.SerializeLayers(buffer, options, ip, udp, payload)
	if err != nil {
		return 0, fmt.Errorf("failed to serialize packet: %v", err)
	}

	send := buffer.Bytes()
	sendBuffer := make([]byte, 40, len(send)+40)
	sendBuffer = append(sendBuffer, send...)

	return r.device.Write([][]byte{sendBuffer}, 40)
}

// Close closes the connection.
func (r *responseWriter) Close() error {
	return nil
}

// TsigStatus returns the status of the Tsig.
func (r *responseWriter) TsigStatus() error {
	return nil
}

// TsigTimersOnly sets the tsig timers only boolean.
func (r *responseWriter) TsigTimersOnly(bool) {
}

// Hijack lets the caller take over the connection.
// After a call to Hijack(), the DNS package will not do anything with the connection.
func (r *responseWriter) Hijack() {
}
