package client

import (
	"context"
	"time"
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
	select {
	case <-time.After(time.Second):
		_ = g.relayClient.Connect()
	case <-g.ctx.Done():
		return
	}
}
