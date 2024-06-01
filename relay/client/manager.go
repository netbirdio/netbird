package client

import (
	"context"
	"fmt"
	"net"
	"sync"
)

type Manager struct {
	ctx        context.Context
	srvAddress string
	peerID     string

	relayClient    *Client
	reconnectGuard *Guard

	relayClients      map[string]*Client
	relayClientsMutex sync.Mutex
}

func NewManager(ctx context.Context, serverAddress string, peerID string) *Manager {
	return &Manager{
		ctx:          ctx,
		srvAddress:   serverAddress,
		peerID:       peerID,
		relayClients: make(map[string]*Client),
	}
}

func (m *Manager) Serve() error {
	m.relayClient = NewClient(m.ctx, m.srvAddress, m.peerID)
	m.reconnectGuard = NewGuard(m.ctx, m.relayClient)
	m.relayClient.SetOnDisconnectListener(m.reconnectGuard.OnDisconnected)
	err := m.relayClient.Connect()
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) OpenConn(serverAddress, peerKey string) (net.Conn, error) {
	if m.relayClient == nil {
		return nil, fmt.Errorf("relay client not connected")
	}

	foreign, err := m.isForeignServer(serverAddress)
	if err != nil {
		return nil, err
	}

	if foreign {
		return m.openConnVia(serverAddress, peerKey)
	} else {
		return m.relayClient.OpenConn(peerKey)
	}
}

func (m *Manager) RelayAddress() (net.Addr, error) {
	if m.relayClient == nil {
		return nil, fmt.Errorf("relay client not connected")
	}
	return m.relayClient.RelayRemoteAddress()
}

func (m *Manager) openConnVia(serverAddress, peerKey string) (net.Conn, error) {
	relayClient, ok := m.relayClients[serverAddress]
	if ok {
		return relayClient.OpenConn(peerKey)
	}

	relayClient = NewClient(m.ctx, serverAddress, m.peerID)
	err := relayClient.Connect()
	if err != nil {
		return nil, err
	}
	relayClient.SetOnDisconnectListener(func() {
		m.deleteRelayConn(serverAddress)
	})
	conn, err := relayClient.OpenConn(peerKey)
	if err != nil {
		return nil, err
	}

	m.relayClients[serverAddress] = relayClient

	return conn, nil
}

func (m *Manager) deleteRelayConn(address string) {
	delete(m.relayClients, address)
}

func (m *Manager) isForeignServer(address string) (bool, error) {
	rAddr, err := m.relayClient.RelayRemoteAddress()
	if err != nil {
		return false, fmt.Errorf("relay client not connected")
	}
	return rAddr.String() != address, nil
}
