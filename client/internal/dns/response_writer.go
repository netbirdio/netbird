package dns

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"github.com/netbirdio/netbird/iface"
)

type responseWriter struct {
	local       net.Addr
	remote      net.Addr
	wgInterface *iface.WGIface
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
		return err
	}
	_, err = r.Write(buff)
	return err
}

// Write writes a raw buffer back to the client.
func (r *responseWriter) Write(data []byte) (int, error) {
	local := r.local.(*net.UDPAddr)
	remote := r.remote.(*net.UDPAddr)

	var ipLayer gopacket.NetworkLayer
	// Create the IP layer
	ipLayer = &layers.IPv4{
		SrcIP: local.IP,
		DstIP: remote.IP,
	}
	if remote.IP.To4() == nil {
		ipLayer = &layers.IPv6{
			SrcIP: local.IP,
			DstIP: remote.IP,
		}
	}

	// Create the UDP layer
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(local.Port),
		DstPort: layers.UDPPort(remote.Port),
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return 0, fmt.Errorf("failed to set network layer for checksum: %v", err)
	}

	// Create the payload layer
	payloadLayer := gopacket.Payload(data)

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	var err error
	if remote.IP.To4() == nil {
		err = gopacket.SerializeLayers(buffer, options, ipLayer.(*layers.IPv6), udpLayer, payloadLayer)
	} else {
		err = gopacket.SerializeLayers(buffer, options, ipLayer.(*layers.IPv4), udpLayer, payloadLayer)
	}
	if err != nil {
		return 0, fmt.Errorf("failed serialize network packet: %v", err)
	}

	return r.wgInterface.GetDevice().Write([][]byte{buffer.Bytes()}, 0)
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
