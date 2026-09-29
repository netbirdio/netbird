package peer

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/peer/dispatcher"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
)

// newP2POnlyConn builds a Conn whose ICE connection is up while its relay
// standby is down, the state of every P2P peer on a routing peer whose relay
// proxies failed. The guard runs against the real status evaluation.
func newP2POnlyConn(t *testing.T, ctx context.Context) *Conn {
	t.Helper()

	statusRecorder := NewRecorder("https://mgm")
	require.NoError(t, statusRecorder.AddPeer(connConf.Key, "remote.netbird", "100.64.0.2", ""))

	config := connConf
	stunTurn := &icemaker.StunTurn{}
	stunTurn.Store(nil)
	config.ICEConfig.StunTurn = stunTurn
	config.WgConfig = WgConfig{
		WgListenPort: 51820,
		RemoteKey:    connConf.Key,
		WgInterface:  &relayTestWGIface{proxies: []*relayTestProxy{{}}},
		AllowedIps:   []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
	}

	relayMgr := relayClient.NewManager(ctx, []string{"rel://127.0.0.1:1"}, connConf.LocalKey, iface.DefaultMTU)
	signaler := NewSignaler(stubSignalClient{}, wgtypes.Key{})
	conn, err := NewConn(config, ServiceDependencies{
		StatusRecorder:     statusRecorder,
		Signaler:           signaler,
		RelayManager:       relayMgr,
		SrWatcher:          guard.NewSRWatcher(nil, nil, nil, config.ICEConfig),
		PeerConnDispatcher: dispatcher.NewConnectionDispatcher(),
	})
	require.NoError(t, err)

	connLog := log.WithField("test", t.Name())
	conn.ctx = ctx
	conn.metricsStages = &MetricsStages{}
	conn.workerRelay = NewWorkerRelay(ctx, connLog, isController(config), config, conn, relayMgr)
	conn.workerRelay.relaySupportedOnRemotePeer.Store(true)
	conn.workerICE, err = NewWorkerICE(ctx, connLog, config, conn, signaler, nil, statusRecorder, true)
	require.NoError(t, err)
	conn.handshaker = NewHandshaker(connLog, config, signaler, conn.workerICE, conn.workerRelay, conn.metricsStages)
	conn.guard = guard.NewGuard(connLog, conn.isConnectedOnAllWay, 100*time.Millisecond, conn.srWatcher, nil)
	conn.statusICE.SetConnected()
	return conn
}

// TestConn_RemoteRestartsDoNotRefillRetryBudget covers a remote peer that keeps
// restarting a working ICE session while the local relay standby is down. Each
// restart makes this side tear down its agent to follow it. Those teardowns
// must not hand the guard a fresh retry budget, or the peer keeps offering
// right after every restart for as long as the remote keeps restarting.
func TestConn_RemoteRestartsDoNotRefillRetryBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conn := newP2POnlyConn(t, ctx)
	var offers atomic.Int32
	go conn.guard.Start(ctx, func() { offers.Add(1) })

	require.Eventually(t, func() bool { return offers.Load() == 3 }, 15*time.Second, 20*time.Millisecond,
		"the guard must spend its partial budget on the missing relay")
	require.Never(t, func() bool { return offers.Load() > 3 }, 1500*time.Millisecond, 20*time.Millisecond,
		"an exhausted budget must leave the guard waiting for the hourly retry")

	for range 5 {
		// The replaced agent's cleanup reports a restart that followed the
		// remote, and the renegotiation connects again right after.
		conn.onICEStateDisconnected(true)
		conn.statusICE.SetConnected()
		time.Sleep(1500 * time.Millisecond)
	}

	assert.Equal(t, int32(3), offers.Load(), "following remote restarts must not refill the retry budget")
}
