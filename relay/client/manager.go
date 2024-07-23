package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	relayAuth "github.com/netbirdio/netbird/relay/auth/hmac"
)

var (
	relayCleanupInterval = 60 * time.Second

	errRelayClientNotConnected = fmt.Errorf("relay client not connected")
)

// RelayTrack hold the relay clients for the foreign relay servers.
// With the mutex can ensure we can open new connection in case the relay connection has been established with
// the relay server.
type RelayTrack struct {
	sync.RWMutex
	relayClient *Client
}

func NewRelayTrack() *RelayTrack {
	return &RelayTrack{}
}

type ManagerService interface {
	Serve() error
	OpenConn(serverAddress, peerKey string, onClosedListener func()) (net.Conn, error)
	RelayInstanceAddress() (string, error)
	ServerURL() string
	HasRelayAddress() bool
	UpdateToken(token *relayAuth.Token)
}

// Manager is a manager for the relay client. It establish one persistent connection to the given relay server. In case
// of network error the manager will try to reconnect to the server.
// The manager also manage temproary relay connection. If a client wants to communicate with an another client on a
// different relay server, the manager will establish a new connection to the relay server. The connection with these
// relay servers will be closed if there is no active connection. Periodically the manager will check if there is any
// unused relay connection and close it.
type Manager struct {
	ctx        context.Context
	serverURL  string
	peerID     string
	tokenStore *relayAuth.TokenStore

	relayClient    *Client
	reconnectGuard *Guard

	relayClients      map[string]*RelayTrack
	relayClientsMutex sync.RWMutex

	onDisconnectedListeners map[string]map[*func()]struct{}
	listenerLock            sync.Mutex
}

func NewManager(ctx context.Context, serverURL string, peerID string) *Manager {
	return &Manager{
		ctx:                     ctx,
		serverURL:               serverURL,
		peerID:                  peerID,
		tokenStore:              &relayAuth.TokenStore{},
		relayClients:            make(map[string]*RelayTrack),
		onDisconnectedListeners: make(map[string]map[*func()]struct{}),
	}
}

// Serve starts the manager. It will establish a connection to the relay server and start the relay cleanup loop.
func (m *Manager) Serve() error {
	if m.relayClient != nil {
		return fmt.Errorf("manager already serving")
	}

	m.relayClient = NewClient(m.ctx, m.serverURL, m.tokenStore, m.peerID)
	err := m.relayClient.Connect()
	if err != nil {
		log.Errorf("failed to connect to relay server: %s", err)
		return err
	}

	m.reconnectGuard = NewGuard(m.ctx, m.relayClient)
	m.relayClient.SetOnDisconnectListener(func() {
		m.onServerDisconnected(m.serverURL)
	})
	m.startCleanupLoop()

	return nil
}

// OpenConn opens a connection to the given peer key. If the peer is on the same relay server, the connection will be
// established via the relay server. If the peer is on a different relay server, the manager will establish a new
// connection to the relay server.
func (m *Manager) OpenConn(serverAddress, peerKey string, onClosedListener func()) (net.Conn, error) {
	if m.relayClient == nil {
		return nil, errRelayClientNotConnected
	}

	foreign, err := m.isForeignServer(serverAddress)
	if err != nil {
		return nil, err
	}

	var (
		netConn net.Conn
	)
	if !foreign {
		log.Debugf("open peer connection via permanent server: %s", peerKey)
		netConn, err = m.relayClient.OpenConn(peerKey)
	} else {
		log.Debugf("open peer connection via foreign server: %s", serverAddress)
		netConn, err = m.openConnVia(serverAddress, peerKey)
	}
	if err != nil {
		return nil, err
	}

	if onClosedListener != nil {
		var listenerAddr string
		if foreign {
			m.addListener(serverAddress, onClosedListener)
			listenerAddr = serverAddress
		} else {
			listenerAddr = m.serverURL
		}
		m.addListener(listenerAddr, onClosedListener)

	}

	return netConn, err
}

// RelayInstanceAddress returns the address of the permanent relay server. It could change if the network connection is lost.
// This address will be sent to the target peer to choose the common relay server for the communication.
func (m *Manager) RelayInstanceAddress() (string, error) {
	if m.relayClient == nil {
		return "", errRelayClientNotConnected
	}
	return m.relayClient.ServerInstanceURL()
}

// ServerURL returns the address of the permanent relay server.
func (m *Manager) ServerURL() string {
	return m.serverURL
}

func (m *Manager) HasRelayAddress() bool {
	return m.serverURL != ""
}

func (m *Manager) UpdateToken(token *relayAuth.Token) {
	m.tokenStore.UpdateToken(token)
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

	relayClient := NewClient(m.ctx, serverAddress, m.tokenStore, m.peerID)
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
		m.onServerDisconnected(serverAddress)
	})
	rt.relayClient = relayClient
	rt.Unlock()

	conn, err := relayClient.OpenConn(peerKey)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (m *Manager) onServerDisconnected(serverAddress string) {
	if serverAddress == m.serverURL {
		go m.reconnectGuard.OnDisconnected()
	}

	m.notifyOnDisconnectListeners(serverAddress)
}

func (m *Manager) isForeignServer(address string) (bool, error) {
	rAddr, err := m.relayClient.ServerInstanceURL()
	if err != nil {
		return false, fmt.Errorf("relay client not connected")
	}
	return rAddr != address, nil
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
		log.Debugf("clean up unused relay server connection: %s", addr)
		delete(m.relayClients, addr)
		rt.Unlock()
	}
}

func (m *Manager) addListener(serverAddress string, onClosedListener func()) {
	m.listenerLock.Lock()
	defer m.listenerLock.Unlock()
	l, ok := m.onDisconnectedListeners[serverAddress]
	if !ok {
		l = make(map[*func()]struct{})
	}
	l[&onClosedListener] = struct{}{}
	m.onDisconnectedListeners[serverAddress] = l
}

func (m *Manager) notifyOnDisconnectListeners(serverAddress string) {
	m.listenerLock.Lock()
	defer m.listenerLock.Unlock()

	l, ok := m.onDisconnectedListeners[serverAddress]
	if !ok {
		return
	}
	for f := range l {
		go (*f)()
	}
	delete(m.onDisconnectedListeners, serverAddress)
}
