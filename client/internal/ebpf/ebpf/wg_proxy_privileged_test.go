//go:build linux && !android && privileged

package ebpf

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const xdpPass = 2

// TestWGProxyXDP_Classification runs the compiled program through the kernel's
// test runner, so it checks the real classifier without attaching it to lo.
// Only packets WireGuard sends to a relayed endpoint may be redirected to the
// proxy; everything the proxy injects towards WireGuard must pass untouched.
func TestWGProxyXDP_Classification(t *testing.T) {
	const (
		wgPort    = 51820
		proxyPort = 3128
		relayPort = 5000
	)

	require.NoError(t, rlimit.RemoveMemlock())
	var objs bpfObjects
	require.NoError(t, loadBpfObjects(&objs, nil), "load eBPF objects")
	t.Cleanup(func() { _ = objs.Close() })

	require.NoError(t, objs.NbWgProxySettingsMap.Put(mapKeyProxyPort, uint16(proxyPort)))
	require.NoError(t, objs.NbWgProxySettingsMap.Put(mapKeyWgPort, uint16(wgPort)))
	require.NoError(t, objs.NbFeatures.Put(mapKeyFeatures, uint16(featureFlagWGProxy)))

	loopback := net.IPv4(127, 0, 0, 1)
	remote := net.IPv4(192, 0, 2, 10)

	tests := []struct {
		name        string
		src, dst    net.UDPAddr
		wantSrcPort uint16
		wantDstPort uint16
	}{
		{
			name:        "WireGuard to relayed endpoint is redirected to the proxy",
			src:         net.UDPAddr{IP: loopback, Port: wgPort},
			dst:         net.UDPAddr{IP: loopback, Port: relayPort},
			wantSrcPort: relayPort,
			wantDstPort: proxyPort,
		},
		{
			name:        "relayed packet injected from the relayed endpoint passes",
			src:         net.UDPAddr{IP: loopback, Port: relayPort},
			dst:         net.UDPAddr{IP: loopback, Port: wgPort},
			wantSrcPort: relayPort,
			wantDstPort: wgPort,
		},
		{
			// RedirectAs injects relayed packets with the remote ICE endpoint
			// as source, and remote peers commonly listen on the same port.
			name:        "relayed packet injected as a remote on the WireGuard port passes",
			src:         net.UDPAddr{IP: remote, Port: wgPort},
			dst:         net.UDPAddr{IP: loopback, Port: wgPort},
			wantSrcPort: wgPort,
			wantDstPort: wgPort,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ret, out, err := objs.NbXdpProg.Test(udpFrame(t, tc.src, tc.dst))
			require.NoError(t, err, "run XDP program")
			assert.Equal(t, uint32(xdpPass), ret, "the program must never drop loopback traffic")

			udp := decodeUDP(t, out)
			assert.Equal(t, tc.wantSrcPort, uint16(udp.SrcPort), "source port after XDP")
			assert.Equal(t, tc.wantDstPort, uint16(udp.DstPort), "destination port after XDP")
		})
	}
}

func udpFrame(t *testing.T, src, dst net.UDPAddr) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    src.IP.To4(),
		DstIP:    dst.IP.To4(),
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(src.Port), DstPort: layers.UDPPort(dst.Port)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload("wireguard")))
	return buf.Bytes()
}

func decodeUDP(t *testing.T, frame []byte) *layers.UDP {
	t.Helper()

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	require.True(t, ok, "the program output must still be a UDP packet")
	return udp
}
