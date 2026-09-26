package peer

import (
	"context"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/netevents"
)

type networkRecorderStub struct{}

func (networkRecorderStub) SetNetworkAvailable(bool) {}

// TestICEAgentSweptOnNetworkChange covers direct paths that must not wait for ICE timeouts.
func TestICEAgentSweptOnNetworkChange(t *testing.T) {
	for _, offline := range []bool{false, true} {
		name := "handover"
		if offline {
			name = "offline"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			manager := netevents.NewManager(networkRecorderStub{})
			worker := &WorkerICE{ctx: ctx, log: log.NewEntry(log.New()), config: ConnConfig{
				NetMgr: manager, ICEConfig: icemaker.Config{StunTurn: &icemaker.StunTurn{}},
			}}
			agent, release, err := worker.reCreateAgent(cancel, []ice.CandidateType{ice.CandidateTypeHost})
			require.NoError(t, err)
			defer release()
			defer agent.Close()
			if offline {
				manager.SetNetworkAvailable(false)
			} else {
				manager.NotifyNetworkChange()
			}
			require.Eventually(t, func() bool {
				_, _, err := agent.GetLocalUserCredentials()
				return err != nil
			}, 2*time.Second, 10*time.Millisecond, "network changes must close ICE without waiting for peer timeouts")
		})
	}
}

// TestICEAgentCreatedAfterNetworkChangeSurvivesPendingSweep protects recovery on the new path.
func TestICEAgentCreatedAfterNetworkChangeSurvivesPendingSweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := netevents.NewManager(networkRecorderStub{})
	manager.NotifyNetworkChange()
	worker := &WorkerICE{ctx: ctx, log: log.NewEntry(log.New()), config: ConnConfig{
		NetMgr: manager, ICEConfig: icemaker.Config{StunTurn: &icemaker.StunTurn{}},
	}}
	agent, release, err := worker.reCreateAgent(cancel, []ice.CandidateType{ice.CandidateTypeHost})
	require.NoError(t, err)
	defer release()
	defer agent.Close()
	require.Never(t, func() bool {
		_, _, err := agent.GetLocalUserCredentials()
		return err != nil
	}, time.Second, 10*time.Millisecond, "a pending sweep must preserve ICE agents created on the new network")
}

// Normal teardown must release the sweep registration without an ICE callback.
func TestICEAgentTeardownWithoutStateCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialCtx, dialCancel := context.WithCancel(ctx)
	worker := &WorkerICE{ctx: ctx, log: log.NewEntry(log.New()), config: ConnConfig{
		NetMgr:    netevents.NewManager(networkRecorderStub{}),
		ICEConfig: icemaker.Config{StunTurn: &icemaker.StunTurn{}},
	}}
	agent, release, err := worker.reCreateAgent(dialCancel, []ice.CandidateType{ice.CandidateTypeHost})
	require.NoError(t, err)
	defer release()
	defer agent.Close()
	// Remove the fallback callback: cancellation must own cleanup itself.
	require.NoError(t, agent.OnConnectionStateChange(func(ice.ConnectionState) {}))
	release()
	release() // Terminal callbacks and explicit teardown may race; release is idempotent.
	require.ErrorIs(t, dialCtx.Err(), context.Canceled)
	require.Eventually(t, func() bool {
		_, _, err := agent.GetLocalUserCredentials()
		return err != nil
	}, time.Second, time.Millisecond, "releasing the registration must close the agent without a network event")
}
