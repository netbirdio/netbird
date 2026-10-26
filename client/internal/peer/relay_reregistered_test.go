package peer

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
)

type recordingWGIface struct {
	stubWGIface
	lastHandshake time.Time
	statsErr      error
	calls         []string
}

func (r *recordingWGIface) UpdatePeer(_ string, _ []netip.Prefix, _ time.Duration, endpoint *net.UDPAddr, _ *wgtypes.Key) error {
	r.calls = append(r.calls, "update "+endpoint.String())
	return nil
}

func (r *recordingWGIface) RemoveEndpointAddress(string) error {
	r.calls = append(r.calls, "remove endpoint")
	return nil
}

func (r *recordingWGIface) GetStats() (map[string]configurer.WGStats, error) {
	if r.statsErr != nil {
		return nil, r.statsErr
	}
	return map[string]configurer.WGStats{
		"LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=": {LastHandshake: r.lastHandshake},
	}, nil
}

type endpointOnlyProxy struct {
	wgproxy.Proxy
	addr *net.UDPAddr
}

func (p *endpointOnlyProxy) EndpointAddr() *net.UDPAddr { return p.addr }

// A remote that registers on the relay again was unreachable at its previous
// registration, so the handshakes sent there were lost. The initiator restarts the
// handshake right away instead of waiting for the rekey timeout, but leaves an
// endpoint that already completed a handshake alone.
func TestConn_onRelayPeerReregistered(t *testing.T) {
	const (
		localKey  = "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU="
		remoteKey = "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU="
		lowKey    = "AAHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU="
	)
	endpoint := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}
	restart := []string{"remove endpoint", "update " + endpoint.String()}
	setAt := time.Now().Add(-time.Second)

	tests := []struct {
		name          string
		localKey      string
		lastHandshake time.Time
		statsErr      error
		superseded    bool
		want          []string
	}{
		{name: "no handshake since the endpoint was set", localKey: localKey, want: restart},
		{name: "handshake before the endpoint was set", localKey: localKey, lastHandshake: setAt.Add(-time.Minute), want: restart},
		{name: "handshake completed over the relay", localKey: localKey, lastHandshake: setAt.Add(100 * time.Millisecond)},
		{name: "responder leaves the handshake to the initiator", localKey: lowKey},
		{name: "superseded relayed connection", localKey: localKey, superseded: true},
		{name: "handshake state unknown", localKey: localKey, statsErr: errors.New("no device")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var disconnected []string
			conn := newWGTimeoutTestConn(false, &disconnected)
			conn.config.LocalKey = tc.localKey
			wgIface := &recordingWGIface{lastHandshake: tc.lastHandshake, statsErr: tc.statsErr}
			conn.config.WgConfig.WgInterface = wgIface
			conn.endpointUpdater = NewEndpointUpdater(conn.Log, conn.config.WgConfig, isController(conn.config))

			relayedConn := &relayClient.Conn{}
			conn.relayedConnRef = relayedConn
			conn.wgProxyRelay = &endpointOnlyProxy{addr: endpoint}
			conn.currentConnPriority = conntype.Relay
			conn.relayEndpointSetAt = setAt

			reported := relayedConn
			if tc.superseded {
				reported = &relayClient.Conn{}
			}
			conn.onRelayPeerReregistered(reported)

			assert.Equal(t, tc.want, wgIface.calls, "interface calls")
			if tc.want != nil {
				assert.True(t, conn.relayEndpointSetAt.After(setAt), "a restarted handshake should move the endpoint set time")
			}
		})
	}
}

// A re-registration reported while the relayed connection is still being set up must
// not be lost: it is applied once the setup completes.
func TestConn_relayReregisteredDuringSetup(t *testing.T) {
	const (
		localKey = "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU="
	)
	endpoint := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}

	var disconnected []string
	conn := newWGTimeoutTestConn(false, &disconnected)
	conn.config.LocalKey = localKey
	wgIface := &recordingWGIface{}
	conn.config.WgConfig.WgInterface = wgIface
	conn.endpointUpdater = NewEndpointUpdater(conn.Log, conn.config.WgConfig, isController(conn.config))

	relayedConn := &relayClient.Conn{}
	conn.onRelayPeerReregistered(relayedConn)
	assert.Empty(t, wgIface.calls, "nothing to restart before the connection is set up")

	conn.mu.Lock()
	conn.relayedConnRef = relayedConn
	conn.wgProxyRelay = &endpointOnlyProxy{addr: endpoint}
	conn.currentConnPriority = conntype.Relay
	conn.relayEndpointSetAt = time.Now().Add(-time.Second)
	conn.applyEarlyRelayReregistrationLocked(relayedConn)
	conn.mu.Unlock()

	assert.Equal(t, []string{"remove endpoint", "update " + endpoint.String()}, wgIface.calls, "interface calls")

	wgIface.calls = nil
	conn.mu.Lock()
	conn.applyEarlyRelayReregistrationLocked(relayedConn)
	conn.mu.Unlock()
	assert.Empty(t, wgIface.calls, "a recorded re-registration is applied once")
}
