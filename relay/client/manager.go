package client

import (
	"context"
	"fmt"
	"net"
)

// Manager todo: thread safe
type Manager struct {
	ctx        context.Context
	srvAddress string
	peerID     string

	relayClient *Client

	relayClients map[string]*Client
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
	err := m.relayClient.Connect()
	if err != nil {
		return err
	}
	return nil
}

func (m *Manager) RelayAddress() (net.Addr, error) {
	if m.relayClient == nil {
		return nil, fmt.Errorf("relay client not connected")
	}
	return m.relayClient.RelayRemoteAddress()
}

func (m *Manager) OpenConn(peerKey string) (net.Conn, error) {
	if m.relayClient == nil {
		return nil, fmt.Errorf("relay client not connected")
	}

	rAddr, err := m.relayClient.RelayRemoteAddress()
	if err != nil {
		return nil, fmt.Errorf("relay client not connected")
	}

	return m.OpenConnTo(rAddr.String(), peerKey)
}

func (m *Manager) OpenConnTo(serverAddress, peerKey string) (net.Conn, error) {
	if m.relayClient == nil {
		return nil, fmt.Errorf("relay client not connected")
	}
	rAddr, err := m.relayClient.RelayRemoteAddress()
	if err != nil {
		return nil, fmt.Errorf("relay client not connected")
	}

	if rAddr.String() == serverAddress {
		return m.relayClient.OpenConn(peerKey)
	}

	relayClient, ok := m.relayClients[serverAddress]
	if ok {
		return relayClient.OpenConn(peerKey)
	}

	relayClient = NewClient(m.ctx, serverAddress, m.peerID)
	err = relayClient.ConnectWithoutReconnect()
	if err != nil {
		return nil, err
	}

	conn, err := relayClient.OpenConn(peerKey)
	if err != nil {
		return nil, err
	}

	m.relayClients[serverAddress] = relayClient
	return conn, nil
}
