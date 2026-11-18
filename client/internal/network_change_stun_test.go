package internal

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/internal/networkmonitor"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/client/netevents"
)

// fakeSTUN answers every binding request with the public address it is told
// to report, standing in for the NAT the host sits behind.
func fakeSTUN(t *testing.T, public *atomic.Pointer[net.UDPAddr]) net.Addr {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			req := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
			if err := req.Decode(); err != nil {
				continue
			}
			addr := public.Load()
			resp, err := stun.Build(req, stun.BindingSuccess, &stun.XORMappedAddress{IP: addr.IP, Port: addr.Port}, stun.Fingerprint)
			if err != nil {
				continue
			}
			_, _ = conn.WriteTo(resp.Raw, from)
		}
	}()
	return conn.LocalAddr()
}

// Alice's laptop gets a new DHCP lease behind another NAT. The address change
// needs no socket rebind, yet the server-reflexive address cached for the old
// network must not be what the P2P renegotiation advertises.
func TestRedialForgetsTheOldNetworksSTUNMapping(t *testing.T) {
	oldNAT := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 40000}
	newNAT := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 50000}
	var public atomic.Pointer[net.UDPAddr]
	public.Store(oldNAT)
	server := fakeSTUN(t, &public)

	sock, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sock.Close() })
	mux := udpmux.NewUniversalUDPMuxDefault(udpmux.UniversalUDPMuxParams{UDPConn: sock, MTU: 1280})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go mux.ReadFromConn(ctx)

	mapped, err := mux.GetXORMappedAddr(server, 2*time.Second)
	require.NoError(t, err)
	require.True(t, mapped.IP.Equal(oldNAT.IP), "the first lookup learns the old network's mapping")

	public.Store(newNAT)
	e := &Engine{
		ctx:       ctx,
		netMgr:    netevents.NewManager(peer.NewRecorder("")),
		peerStore: peerstore.NewConnStore(),
		udpMux:    mux,
	}
	require.True(t, e.redialOnUnderlayChange(networkmonitor.Change{Kind: networkmonitor.ChangeAddress}), "an address change is handled in place")

	mapped, err = mux.GetXORMappedAddr(server, 2*time.Second)
	require.NoError(t, err)
	assert.True(t, mapped.IP.Equal(newNAT.IP), "after the change the mapping is asked again, got %s", mapped.IP)
}
