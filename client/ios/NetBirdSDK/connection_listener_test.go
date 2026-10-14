//go:build ios

package NetBirdSDK

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type recordingConnectionListener struct {
	connecting int
}

func (*recordingConnectionListener) OnConnected()                    {}
func (*recordingConnectionListener) OnDisconnected()                 {}
func (l *recordingConnectionListener) OnConnecting()                 { l.connecting++ }
func (*recordingConnectionListener) OnDisconnecting()                {}
func (*recordingConnectionListener) OnAddressChanged(string, string) {}
func (*recordingConnectionListener) OnPeersListChanged(int)          {}

func TestConnectionListenerReportsNetworkLoss(t *testing.T) {
	listener := &recordingConnectionListener{}
	adapter := connectionListenerAdapter{listener}

	adapter.OnStateChanged(peer.ClientStateNoNetwork)
	assert.Equal(t, 1, listener.connecting, "network loss must reach the legacy reconnecting callback")

	for _, state := range []peer.ClientState{
		peer.ClientStateDisconnected,
		peer.ClientStateConnected,
		peer.ClientStateConnecting,
		peer.ClientStateDisconnecting,
	} {
		adapter.OnStateChanged(state)
	}
	assert.Equal(t, 1, listener.connecting, "states with legacy callbacks must not emit duplicate reconnecting callbacks")
}
