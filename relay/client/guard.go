package client

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	reconnectingTimeout = 5 * time.Second
)

type Guard struct {
	ctx         context.Context
	relayClient *Client
}

func NewGuard(context context.Context, relayClient *Client) *Guard {
	g := &Guard{
		ctx:         context,
		relayClient: relayClient,
	}
	return g
}

func (g *Guard) OnDisconnected() {
	// todo prevent multiple reconnect
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
