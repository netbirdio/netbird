//go:build ios

package NetBirdSDK

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type recordingConnectionListener struct {
	connecting int
	states     []int
}

func (l *recordingConnectionListener) OnStateChanged(state int) { l.states = append(l.states, state) }

func (*recordingConnectionListener) OnConnected()                    {}
func (*recordingConnectionListener) OnDisconnected()                 {}
func (l *recordingConnectionListener) OnConnecting()                 { l.connecting++ }
func (*recordingConnectionListener) OnDisconnecting()                {}
func (*recordingConnectionListener) OnAddressChanged(string, string) {}
func (*recordingConnectionListener) OnPeersListChanged(int)          {}

func TestConnectionListenerForwardsStates(t *testing.T) {
	listener := &recordingConnectionListener{}
	adapter := connectionListenerAdapter{listener}
	states := []peer.ClientState{
		peer.ClientStateDisconnected,
		peer.ClientStateConnected,
		peer.ClientStateConnecting,
		peer.ClientStateDisconnecting,
		peer.ClientStateNoNetwork,
	}
	var want []int
	for _, state := range states {
		adapter.OnStateChanged(state)
		want = append(want, int(state))
	}
	assert.Equal(t, want, listener.states)
	assert.Zero(t, listener.connecting, "state forwarding must not synthesize legacy callbacks")
}
