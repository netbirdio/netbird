package client

import (
	"context"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type Manager struct {
	ctx        context.Context
	srvAddress string
	peerID     string

	reconnectTime time.Duration

	mu     sync.Mutex
	client *Client
}

func NewManager(ctx context.Context, serverAddress string, peerID string) *Manager {
	return &Manager{
		ctx:           ctx,
		srvAddress:    serverAddress,
		peerID:        peerID,
		reconnectTime: 5 * time.Second,
	}
}

func (m *Manager) Serve() {
	ok := m.mu.TryLock()
	if !ok {
		return
	}

	m.client = NewClient(m.ctx, m.srvAddress, m.peerID)

	go func() {
		defer m.mu.Unlock()

		// todo this is not thread safe
		for {
			select {
			case <-m.ctx.Done():
				return
			default:
				m.connect()
			}

			select {
			case <-m.ctx.Done():
				return
			case <-time.After(2 * time.Second): //timeout
			}
		}
	}()
}

func (m *Manager) OpenConn(peerKey string) (net.Conn, error) {
	// todo m.client nil check
	return m.client.OpenConn(peerKey)
}

// connect is blocking
func (m *Manager) connect() {
	err := m.client.Connect()
	if err != nil {
		if m.ctx.Err() != nil {
			return
		}
		log.Errorf("connection error with '%s': %s", m.srvAddress, err)
	}
}
