package client

import (
	"context"
	"sync"
)

type Manager struct {
	ctx        context.Context
	ctxCancel  context.CancelFunc
	srvAddress string
	peerID     string

	wg sync.WaitGroup

	clients      map[string]*Client
	clientsMutex sync.RWMutex
}

func NewManager(ctx context.Context, serverAddress string, peerID string) *Manager {
	ctx, cancel := context.WithCancel(ctx)
	return &Manager{
		ctx:        ctx,
		ctxCancel:  cancel,
		srvAddress: serverAddress,
		peerID:     peerID,
		clients:    make(map[string]*Client),
	}
}

func (m *Manager) Teardown() {
	m.ctxCancel()
	m.wg.Wait()
}

func (m *Manager) newSrvConnection(address string) {
	if _, ok := m.clients[address]; ok {
		return
	}

	//	client := NewClient(address, m.peerID)
	//err = client.Connect()
}
