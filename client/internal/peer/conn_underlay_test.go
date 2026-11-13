package peer

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
)

// A lazy connection sits in the peer store and the status recorder without
// ever being opened, so it has no context and no workers yet.
func TestOnUnderlayChangedSkipsUnopenedConn(t *testing.T) {
	conn := newUnopenedConn(t)

	assert.NotPanics(t, func() {
		conn.OnUnderlayChanged(func(netip.Addr) bool { return false }, time.Now(), time.Now().Add(time.Minute))
		conn.MoveMarkedToRelay()
	}, "an underlay change must skip a connection that was never opened")
}

// A peer the status recorder no longer knows cannot be judged, so the mark of
// an earlier change must not survive to move it on a later relay event.
func TestOnUnderlayChangedClearsTheMarkWhenThePeerIsUnknown(t *testing.T) {
	conn := newUnopenedConn(t)
	conn.config.Key = "unknown-peer"
	now := time.Now()
	conn.underlayMark = underlayMark{iceGen: 1, until: now.Add(time.Minute)}

	conn.OnUnderlayChanged(func(netip.Addr) bool { return false }, now, now.Add(time.Minute))

	assert.Equal(t, underlayMark{}, conn.underlayMark, "the stale mark must be cleared")
}

// unresolvableConn is an ICE connection whose remote address cannot be
// resolved, so configuring the WireGuard endpoint fails.
type unresolvableConn struct{ net.Conn }

func (unresolvableConn) RemoteAddr() net.Addr { return unresolvableAddr{} }

type unresolvableAddr struct{}

func (unresolvableAddr) Network() string { return "udp" }
func (unresolvableAddr) String() string  { return "not-an-endpoint" }

// A P2P path that failed to become active must not count as a new one, or the
// mark of the path lost to the change would be dropped and the peer would stay
// on the dead path until the ICE timeouts.
func TestFailedICEActivationKeepsTheMark(t *testing.T) {
	conn := newUnopenedConn(t)
	conn.ctx = context.Background()

	conn.onICEConnectionIsReady(conntype.ICEP2P, ICEConnInfo{RemoteConn: unresolvableConn{}})

	assert.Equal(t, conntype.None, conn.currentConnPriority, "ICE must not be the active path after the failure")
	assert.Zero(t, conn.iceActiveGen, "a failed activation must not count as ICE becoming active")
}

func newUnopenedConn(t *testing.T) *Conn {
	t.Helper()
	recorder := NewRecorder("https://mgm")
	require.NoError(t, recorder.AddPeer(connConf.Key, "peer.netbird", "100.64.0.2", ""))

	config := connConf
	config.WgConfig.AllowedIps = []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}
	conn, err := NewConn(config, ServiceDependencies{
		StatusRecorder:     recorder,
		SrWatcher:          guard.NewSRWatcher(nil, nil, nil, connConf.ICEConfig),
		PeerConnDispatcher: testDispatcher,
	})
	require.NoError(t, err)
	return conn
}

// The network change sweeps the relay too, so a lost P2P path waits for the
// peer's relay connection to come back before it is closed.
func TestUnderlayMarkVerdict(t *testing.T) {
	now := time.Now()
	mark := underlayMark{iceGen: 3, notBefore: now.Add(-time.Second), until: now.Add(time.Minute)}

	tests := []struct {
		name       string
		mark       underlayMark
		iceGen     uint64
		priority   conntype.ConnPriority
		relayReady bool
		want       markVerdict
	}{
		{name: "relay of the peer not back yet", mark: mark, iceGen: 3, priority: conntype.ICEP2P, relayReady: false, want: markWait},
		// A relay connection that came back before the sweep settled may be
		// one the sweep is about to close.
		{name: "relay of the peer back before the sweep settled", mark: underlayMark{iceGen: 3, notBefore: now.Add(time.Second), until: now.Add(time.Minute)}, iceGen: 3, priority: conntype.ICEP2P, relayReady: true, want: markWait},
		{name: "relay of the peer back", mark: mark, iceGen: 3, priority: conntype.ICEP2P, relayReady: true, want: markMove},
		{name: "relay back for a P2P path through TURN", mark: mark, iceGen: 3, priority: conntype.ICETurn, relayReady: true, want: markMove},
		// P2P renegotiated on the new network before the relay came back:
		// closing ICE now would kill the new path.
		{name: "ICE reconnected since the change", mark: mark, iceGen: 4, priority: conntype.ICEP2P, relayReady: true, want: markDrop},
		{name: "peer already left P2P on its own", mark: mark, iceGen: 3, priority: conntype.Relay, relayReady: true, want: markDrop},
		{name: "mark expired", mark: underlayMark{iceGen: 3, until: now.Add(-time.Second)}, iceGen: 3, priority: conntype.ICEP2P, relayReady: true, want: markDrop},
		{name: "no mark", mark: underlayMark{}, iceGen: 0, priority: conntype.ICEP2P, relayReady: true, want: markDrop},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.mark.verdict(tt.iceGen, tt.priority, tt.relayReady, now), "mark verdict")
		})
	}
}

func TestP2PPathLost(t *testing.T) {
	onHost := map[netip.Addr]bool{
		netip.MustParseAddr("10.132.0.3"):  true,
		netip.MustParseAddr("2001:db8::7"): true,
	}
	exists := func(a netip.Addr) bool { return onHost[a] }

	tests := []struct {
		name     string
		candType string
		endpoint string
		want     bool
	}{
		// The old interface is still up, as with a cable plugged while Wi-Fi
		// stays connected: the direct path keeps working.
		{name: "host candidate whose address is still on the host", candType: "host", endpoint: "10.132.0.3:51820", want: false},
		{name: "host candidate on IPv6 still on the host", candType: "host", endpoint: "[2001:db8::7]:51820", want: false},
		{name: "IPv4-mapped host candidate still on the host", candType: "host", endpoint: "[::ffff:10.132.0.3]:51820", want: false},
		// Wi-Fi off or a new DHCP lease: the local end of the path is gone.
		{name: "host candidate whose address is gone", candType: "host", endpoint: "192.168.1.20:51820", want: true},
		// Behind NAT or TURN the path depends on the old network's mapping.
		{name: "server reflexive candidate", candType: "srflx", endpoint: "203.0.113.5:40000", want: true},
		{name: "peer reflexive candidate", candType: "prflx", endpoint: "203.0.113.5:40000", want: true},
		{name: "relay candidate", candType: "relay", endpoint: "198.51.100.9:3478", want: true},
		{name: "unparsable endpoint is treated as lost", candType: "host", endpoint: "not-an-endpoint", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, p2pPathLost(tt.candType, tt.endpoint, exists), "path lost verdict")
		})
	}
}
