package internal

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
	"github.com/netbirdio/netbird/client/internal/netflow"
	"github.com/netbirdio/netbird/client/internal/pqkem"
	"github.com/netbirdio/netbird/client/internal/routemanager"
)

// pqFirewallIface is the minimal overlay interface the userspace firewall attaches to.
type pqFirewallIface struct{ addr wgaddr.Address }

func (i pqFirewallIface) Name() string                        { return "wt-pq-test" }
func (i pqFirewallIface) Address() wgaddr.Address             { return i.addr }
func (i pqFirewallIface) SetFilter(device.PacketFilter) error { return nil }
func (i pqFirewallIface) GetWGDevice() *wgbackend.Device      { return nil }

// firewallOnlyRouteManager accepts the firewall initFirewall hands to the route manager.
type firewallOnlyRouteManager struct{ *routemanager.MockManager }

func (firewallOnlyRouteManager) SetFirewall(firewallManager.Manager) error { return nil }

// pqInboundUDP builds an overlay UDP packet from a peer to the local PQ data-path port.
func pqInboundUDP(t *testing.T, src, dst netip.Addr, port uint16) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP(src.AsSlice()), DstIP: net.IP(dst.AsSlice())}
	udp := &layers.UDP{SrcPort: layers.UDPPort(port), DstPort: layers.UDPPort(port)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload("pq-offer")))
	return buf.Bytes()
}

// pqFirewallWGIface is an overlay interface without netstack, so the PQ transport binds a
// plain OS socket. startPQKEMManager calls nothing else on it.
type pqFirewallWGIface struct{ WGIface }

func (pqFirewallWGIface) GetNet() *wgbackend.NetstackNet { return nil }

// TestEngine_PQKEMStartAllowsItsPort: the PQ transport listens on the overlay, so with peer
// ACLs that do not open its port a rotation offer from a peer is dropped and rotation times
// out. The engine sets the firewall up first and starts the transport later, once the
// interface is up; the port must still end up accepted.
func TestEngine_PQKEMStartAllowsItsPort(t *testing.T) {
	t.Setenv(pqkem.EnvEnabled, "true")
	local := netip.MustParseAddr("100.64.0.1")
	remote := netip.MustParseAddr("100.64.0.2")
	fw, err := uspfilter.Create(uspfilter.Config{
		IFace:      pqFirewallIface{addr: wgaddr.Address{IP: local, Network: netip.MustParsePrefix("100.64.0.0/10")}},
		FlowLogger: netflow.NewManager(nil, []byte{}, nil).GetLogger(),
		MTU:        iface.DefaultMTU,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, fw.Close(nil)) })
	require.NoError(t, fw.UpdateLocalIPs())

	e := &Engine{
		// The transport binds on loopback: the filter only looks at the packet's port.
		config:       &EngineConfig{WgAddr: wgaddr.Address{IP: netip.MustParseAddr("127.0.0.1")}},
		firewall:     fw,
		routeManager: firewallOnlyRouteManager{&routemanager.MockManager{}},
		wgInterface:  pqFirewallWGIface{},
	}
	// Engine.Start order: firewall first, PQ transport after the interface is up.
	require.NoError(t, e.initFirewall())
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	require.NoError(t, e.startPQKEMManager(key.PublicKey()))
	require.NotNil(t, e.pqkemManager, "precondition: the PQ manager started")
	t.Cleanup(e.pqkemManager.Stop)

	packet := pqInboundUDP(t, remote, local, uint16(e.pqkemManager.LocalPort()))
	assert.False(t, fw.FilterInbound(packet, len(packet)), "a peer's PQ data-path message must pass the firewall")

	other := pqInboundUDP(t, remote, local, uint16(e.pqkemManager.LocalPort())+1)
	assert.True(t, fw.FilterInbound(other, len(other)), "only the PQ port may be opened")
}
