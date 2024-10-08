package client

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	reconnectingTimeout = 5 * time.Second
)

// Guard manage the reconnection tries to the Relay server in case of disconnection event.
type Guard struct {
	ctx         context.Context
	relayClient *Client
}

// NewGuard creates a new guard for the relay client.
func NewGuard(context context.Context, relayClient *Client) *Guard {
	g := &Guard{
		ctx:         context,
		relayClient: relayClient,
	}
	return g
}

// OnDisconnected is called when the relay client is disconnected from the relay server. It will trigger the reconnection
// todo prevent multiple reconnection instances. In the current usage it should not happen, but it is better to prevent
func (g *Guard) OnDisconnected() {
	ticker := time.NewTicker(reconnectingTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := g.relayClient.Connect()
			if err != nil {
				log.Errorf("failed to reconnect to relay server: %s", err)
				continue
			}
			return
		case <-g.ctx.Done():
			return
		}
	}
}
