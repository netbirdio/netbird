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
			agent, err := worker.reCreateAgent(cancel, []ice.CandidateType{ice.CandidateTypeHost})
			require.NoError(t, err)
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

func TestICEAgentCreatedAfterNetworkChangeSurvivesPendingSweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := netevents.NewManager(networkRecorderStub{})
	manager.NotifyNetworkChange()
	worker := &WorkerICE{ctx: ctx, log: log.NewEntry(log.New()), config: ConnConfig{
		NetMgr: manager, ICEConfig: icemaker.Config{StunTurn: &icemaker.StunTurn{}},
	}}
	agent, err := worker.reCreateAgent(cancel, []ice.CandidateType{ice.CandidateTypeHost})
	require.NoError(t, err)
	defer agent.Close()
	require.Never(t, func() bool {
		_, _, err := agent.GetLocalUserCredentials()
		return err != nil
	}, time.Second, 10*time.Millisecond, "a pending sweep must preserve ICE agents created on the new network")
}
