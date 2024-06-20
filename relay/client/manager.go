package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	relayCleanupInterval = 60 * time.Second

	errRelayClientNotConnected = fmt.Errorf("relay client not connected")
)

// RelayTrack hold the relay clients for the foregin relay servers.
// With the mutex can ensure we can open new connection in case the relay connection has been established with
// the relay server.
type RelayTrack struct {
	sync.RWMutex
	relayClient *Client
}

func NewRelayTrack() *RelayTrack {
	return &RelayTrack{}
}

// Manager is a manager for the relay client. It establish one persistent connection to the given relay server. In case
// of network error the manager will try to reconnect to the server.
// The manager also manage temproary relay connection. If a client wants to communicate with an another client on a
// different relay server, the manager will establish a new connection to the relay server. The connection with these
// relay servers will be closed if there is no active connection. Periodically the manager will check if there is any
// unused relay connection and close it.
type Manager struct {
	ctx        context.Context
	srvAddress string
	peerID     string

	relayClient    *Client
	reconnectGuard *Guard

	relayClients      map[string]*RelayTrack
	relayClientsMutex sync.RWMutex
}

func NewManager(ctx context.Context, serverAddress string, peerID string) *Manager {
	return &Manager{
		ctx:          ctx,
		srvAddress:   serverAddress,
		peerID:       peerID,
		relayClients: make(map[string]*RelayTrack),
	}
}

// Serve starts the manager. It will establish a connection to the relay server and start the relay cleanup loop.
// todo: consider to return an error if the initial connection to the relay server is not established.
func (m *Manager) Serve() error {
	if m.relayClient != nil {
		return fmt.Errorf("manager already serving")
	}

	m.relayClient = NewClient(m.ctx, m.srvAddress, m.peerID)
	err := m.relayClient.Connect()
	if err != nil {
		log.Errorf("failed to connect to relay server: %s", err)
		return err
	}

	m.reconnectGuard = NewGuard(m.ctx, m.relayClient)
	m.relayClient.SetOnDisconnectListener(m.reconnectGuard.OnDisconnected)

	m.startCleanupLoop()

	return nil
}

// OpenConn opens a connection to the given peer key. If the peer is on the same relay server, the connection will be
// established via the relay server. If the peer is on a different relay server, the manager will establish a new
// connection to the relay server.
func (m *Manager) OpenConn(serverAddress, peerKey string) (net.Conn, error) {
	if m.relayClient == nil {
		return nil, errRelayClientNotConnected
	}

	foreign, err := m.isForeignServer(serverAddress)
	if err != nil {
		return nil, err
	}

	if !foreign {
		log.Debugf("open peer connection via permanent server: %s", peerKey)
		return m.relayClient.OpenConn(peerKey)
	} else {
		log.Debugf("open peer connection via foreign server: %s", serverAddress)
		return m.openConnVia(serverAddress, peerKey)
	}
}

// RelayAddress returns the address of the permanent relay server. It could change if the network connection is lost.
// This address will be sent to the target peer to choose the common relay server for the communication.
func (m *Manager) RelayAddress() (net.Addr, error) {
	if m.relayClient == nil {
		return nil, errRelayClientNotConnected
	}
	return m.relayClient.RelayRemoteAddress()
}

func (m *Manager) HasRelayAddress() bool {
	return m.srvAddress != ""
}

func (m *Manager) openConnVia(serverAddress, peerKey string) (net.Conn, error) {
	// check if already has a connection to the desired relay server
	m.relayClientsMutex.RLock()
	rt, ok := m.relayClients[serverAddress]
	if ok {
		rt.RLock()
		m.relayClientsMutex.RUnlock()
		defer rt.RUnlock()
		return rt.relayClient.OpenConn(peerKey)
	}
	m.relayClientsMutex.RUnlock()

	// if not, establish a new connection but check it again (because changed the lock type) before starting the
	// connection
	m.relayClientsMutex.Lock()
	rt, ok = m.relayClients[serverAddress]
	if ok {
		rt.RLock()
		m.relayClientsMutex.Unlock()
		defer rt.RUnlock()
		return rt.relayClient.OpenConn(peerKey)
	}

	// create a new relay client and store it in the relayClients map
	rt = NewRelayTrack()
	rt.Lock()
	m.relayClients[serverAddress] = rt
	m.relayClientsMutex.Unlock()

	relayClient := NewClient(m.ctx, serverAddress, m.peerID)
	err := relayClient.Connect()
	if err != nil {
		rt.Unlock()
		m.relayClientsMutex.Lock()
		delete(m.relayClients, serverAddress)
		m.relayClientsMutex.Unlock()
		return nil, err
	}
	// if connection closed then delete the relay client from the list
	relayClient.SetOnDisconnectListener(func() {
		m.deleteRelayConn(serverAddress)
	})
	rt.relayClient = relayClient
	rt.Unlock()

	conn, err := relayClient.OpenConn(peerKey)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (m *Manager) deleteRelayConn(address string) {
	log.Infof("deleting relay client for %s", address)
	m.relayClientsMutex.Lock()
	delete(m.relayClients, address)
	m.relayClientsMutex.Unlock()
}

func (m *Manager) isForeignServer(address string) (bool, error) {
	rAddr, err := m.relayClient.RelayRemoteAddress()
	if err != nil {
		return false, fmt.Errorf("relay client not connected")
	}
	return rAddr.String() != address, nil
}

func (m *Manager) startCleanupLoop() {
	if m.ctx.Err() != nil {
		return
	}

	ticker := time.NewTicker(relayCleanupInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.cleanUpUnusedRelays()
			}
		}
	}()
}

func (m *Manager) cleanUpUnusedRelays() {
	m.relayClientsMutex.Lock()
	defer m.relayClientsMutex.Unlock()

	for addr, rt := range m.relayClients {
		rt.Lock()
		if rt.relayClient.HasConns() {
			rt.Unlock()
			continue
		}
		rt.relayClient.SetOnDisconnectListener(nil)
		go func() {
			_ = rt.relayClient.Close()
		}()
		log.Debugf("clean up relay client: %s", addr)
		delete(m.relayClients, addr)
		rt.Unlock()
	}
}
