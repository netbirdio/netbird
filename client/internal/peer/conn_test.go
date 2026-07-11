package peer

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	"github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/metricsstages"
	"github.com/netbirdio/netbird/client/internal/peer/signaling"
	"github.com/netbirdio/netbird/client/internal/peer/status"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/util"
)

var connConf = ConnConfig{
	Key:         "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	LocalKey:    "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	Timeout:     time.Second,
	LocalWgPort: 51820,
	WgConfig: WgConfig{
		AllowedIps: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
	},
	ICEConfig: ice.Config{
		InterfaceBlackList: nil,
	},
}

func TestMain(m *testing.M) {
	_ = util.InitLog("trace", util.LogConsole)
	code := m.Run()
	os.Exit(code)
}

func TestNewConn_interfaceFilter(t *testing.T) {
	ignore := []string{iface.WgInterfaceDefault, "tun0", "zt", "ZeroTier", "utun", "wg", "ts",
		"Tailscale", "tailscale"}

	filter := stdnet.InterfaceFilter(ignore)

	for _, s := range ignore {
		assert.Equal(t, filter(s), false)
	}

}

func TestConn_GetKey(t *testing.T) {
	swWatcher := guard.NewSRWatcher(nil, nil, nil, connConf.ICEConfig)

	sd := ServiceDependencies{
		SrWatcher: swWatcher,
	}
	conn, err := NewConn(connConf, sd)
	require.NoError(t, err)

	got := conn.GetKey()

	assert.Equal(t, got, connConf.Key, "they should be equal")
}

// TestConn_DiscardMessagesWhenNotOpened: signal messages posted to a not yet
// opened connection must be discarded without blocking or panicking.
func TestConn_DiscardMessagesWhenNotOpened(t *testing.T) {
	swWatcher := guard.NewSRWatcher(nil, nil, nil, connConf.ICEConfig)
	sd := ServiceDependencies{
		StatusRecorder: status.NewRecorder("https://mgm"),
		SrWatcher:      swWatcher,
	}
	conn, err := NewConn(connConf, sd)
	require.NoError(t, err)

	offerAnswer := signaling.OfferAnswer{
		IceCredentials: signaling.IceCredentials{
			UFrag: "test",
			Pwd:   "test",
		},
	}
	conn.OnRemoteOffer(offerAnswer)
	conn.OnRemoteAnswer(offerAnswer)
	conn.OnRemoteCandidate(nil, nil)
	conn.Close(false)
}

func TestConn_presharedKey(t *testing.T) {
	conn1 := Conn{
		config: ConnConfig{
			Key:             "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			LocalKey:        "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			RosenpassConfig: RosenpassConfig{},
		},
	}
	conn2 := Conn{
		config: ConnConfig{
			Key:             "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			LocalKey:        "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			RosenpassConfig: RosenpassConfig{},
		},
	}

	tests := []struct {
		conn1Permissive         bool
		conn1RosenpassEnabled   bool
		conn2Permissive         bool
		conn2RosenpassEnabled   bool
		conn1ExpectedInitialKey bool
		conn2ExpectedInitialKey bool
	}{
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   false,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   false,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         true,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   false,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         true,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         true,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         true,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         true,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: true,
		},
	}

	conn1.config.RosenpassConfig.PermissiveMode = true
	for i, test := range tests {
		tcase := i + 1
		t.Run(fmt.Sprintf("Rosenpass test case %d", tcase), func(t *testing.T) {
			conn1.config.RosenpassConfig = RosenpassConfig{}
			conn2.config.RosenpassConfig = RosenpassConfig{}

			if test.conn1RosenpassEnabled {
				conn1.config.RosenpassConfig.PubKey = []byte("dummykey")
			}
			conn1.config.RosenpassConfig.PermissiveMode = test.conn1Permissive

			if test.conn2RosenpassEnabled {
				conn2.config.RosenpassConfig.PubKey = []byte("dummykey")
			}
			conn2.config.RosenpassConfig.PermissiveMode = test.conn2Permissive

			conn1PresharedKey := conn1.presharedKey(conn2.config.RosenpassConfig.PubKey)
			conn2PresharedKey := conn2.presharedKey(conn1.config.RosenpassConfig.PubKey)

			if test.conn1ExpectedInitialKey {
				if conn1PresharedKey == nil {
					t.Errorf("Case %d: Expected conn1 to have a non-nil key, but got nil", tcase)
				}
			} else {
				if conn1PresharedKey != nil {
					t.Errorf("Case %d: Expected conn1 to have a nil key, but got %v", tcase, conn1PresharedKey)
				}
			}

			// Assert conn2's key expectation
			if test.conn2ExpectedInitialKey {
				if conn2PresharedKey == nil {
					t.Errorf("Case %d: Expected conn2 to have a non-nil key, but got nil", tcase)
				}
			} else {
				if conn2PresharedKey != nil {
					t.Errorf("Case %d: Expected conn2 to have a nil key, but got %v", tcase, conn2PresharedKey)
				}
			}
		})
	}
}

func TestConn_presharedKey_RosenpassManaged(t *testing.T) {
	conn := Conn{
		config: ConnConfig{
			Key:             "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			LocalKey:        "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			RosenpassConfig: RosenpassConfig{PubKey: []byte("dummykey")},
		},
	}

	// When Rosenpass has already initialized the PSK for this peer,
	// presharedKey must return nil to avoid UpdatePeer overwriting it.
	conn.rosenpassInitializedPresharedKeyValidator = func(peerKey string) bool { return true }
	if k := conn.presharedKey([]byte("remote")); k != nil {
		t.Fatalf("expected nil presharedKey when Rosenpass manages PSK, got %v", k)
	}

	// When Rosenpass hasn't taken over yet, presharedKey should provide
	// a non-nil initial key (deterministic or from NetBird PSK).
	conn.rosenpassInitializedPresharedKeyValidator = func(peerKey string) bool { return false }
	if k := conn.presharedKey([]byte("remote")); k == nil {
		t.Fatalf("expected non-nil presharedKey before Rosenpass manages PSK")
	}
}

func newWGTimeoutTestConn(rosenpassEnabled bool, disconnected *[]string) *Conn {
	cfg := ConnConfig{
		Key:      "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		LocalKey: "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		WgConfig: WgConfig{RemoteKey: "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU="},
	}
	if rosenpassEnabled {
		cfg.RosenpassConfig = RosenpassConfig{PubKey: []byte("dummykey")}
	}

	conn := &Conn{
		ctx:           context.Background(),
		config:        cfg,
		Log:           log.WithField("peer", cfg.Key),
		metricsStages: &metricsstages.MetricsStages{},
	}
	conn.SetOnDisconnected(func(remotePeer string) {
		*disconnected = append(*disconnected, remotePeer)
	})
	return conn
}

// TestConn_onWGDisconnected_EscalatesToRosenpassReset: repeated handshake
// timeouts with rosenpass enabled mean the preshared keys have desynced. The
// renewal exchange runs over the dead tunnel and cannot resync them, so after
// wgTimeoutEscalationThreshold consecutive timeouts the conn must report the
// peer disconnected, dropping its rosenpass state so the next configuration
// programs the rendezvous key.
func TestConn_onWGDisconnected_EscalatesToRosenpassReset(t *testing.T) {
	var disconnected []string
	conn := newWGTimeoutTestConn(true, &disconnected)

	for i := 0; i < wgTimeoutEscalationThreshold-1; i++ {
		conn.handleWGTimeout()
	}
	assert.Empty(t, disconnected, "escalation must not fire below the threshold")

	conn.handleWGTimeout()
	assert.Equal(t, []string{conn.config.WgConfig.RemoteKey}, disconnected,
		"reaching the threshold must report the peer disconnected once")

	for i := 0; i < wgTimeoutEscalationThreshold-1; i++ {
		conn.handleWGTimeout()
	}
	assert.Len(t, disconnected, 1, "escalation must restart counting after firing")

	conn.handleWGTimeout()
	assert.Len(t, disconnected, 2, "continued timeouts must escalate again")
}

// TestConn_onWGDisconnected_CheckSuccessResetsEscalation: a successful
// handshake between timeouts means the tunnel recovered; the counter must
// start over.
func TestConn_onWGDisconnected_CheckSuccessResetsEscalation(t *testing.T) {
	var disconnected []string
	conn := newWGTimeoutTestConn(true, &disconnected)

	for i := 0; i < wgTimeoutEscalationThreshold-1; i++ {
		conn.handleWGTimeout()
	}
	conn.handleWGCheckSuccess()

	for i := 0; i < wgTimeoutEscalationThreshold-1; i++ {
		conn.handleWGTimeout()
	}
	assert.Empty(t, disconnected, "handshake success must reset the timeout count")
}

// TestConn_onWGDisconnected_NoEscalationWithoutRosenpass: without rosenpass
// there is no per-peer key state to reset; repeated timeouts must not report
// disconnects.
func TestConn_onWGDisconnected_NoEscalationWithoutRosenpass(t *testing.T) {
	var disconnected []string
	conn := newWGTimeoutTestConn(false, &disconnected)

	for i := 0; i < wgTimeoutEscalationThreshold*3; i++ {
		conn.handleWGTimeout()
	}
	assert.Empty(t, disconnected, "escalation must be limited to rosenpass connections")
}
