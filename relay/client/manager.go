package client

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	relayAuth "github.com/netbirdio/netbird/relay/auth/hmac"
)

var (
	relayCleanupInterval = 60 * time.Second
	connectionTimeout    = 30 * time.Second
	maxConcurrentServers = 7

	ErrRelayClientNotConnected = fmt.Errorf("relay client not connected")
)

// RelayTrack hold the relay clients for the foreign relay servers.
// With the mutex can ensure we can open new connection in case the relay connection has been established with
// the relay server.
type RelayTrack struct {
	sync.RWMutex
	relayClient *Client
	err         error
}

func NewRelayTrack() *RelayTrack {
	return &RelayTrack{}
}

type OnServerCloseListener func()

// ManagerService is the interface for the relay manager.
type ManagerService interface {
	Serve() error
	OpenConn(serverAddress, peerKey string) (net.Conn, error)
	AddCloseListener(serverAddress string, onClosedListener OnServerCloseListener) error
	RelayInstanceAddress() (string, error)
	ServerURLs() []string
	HasRelayAddress() bool
	UpdateToken(token *relayAuth.Token) error
}

// Manager is a manager for the relay client instances. It establishes one persistent connection to the given relay URL
// and automatically reconnect to them in case disconnection.
// The manager also manage temporary relay connection. If a client wants to communicate with a client on a
// different relay server, the manager will establish a new connection to the relay server. The connection with these
// relay servers will be closed if there is no active connection. Periodically the manager will check if there is any
// unused relay connection and close it.
type Manager struct {
	ctx        context.Context
	serverURLs []string
	peerID     string
	tokenStore *relayAuth.TokenStore

	relayClient    *Client
	reconnectGuard *Guard

	relayClients      map[string]*RelayTrack
	relayClientsMutex sync.RWMutex

	onDisconnectedListeners map[string]*list.List
	listenerLock            sync.Mutex
}

// NewManager creates a new manager instance.
// The serverURL address can be empty. In this case, the manager will not serve.
func NewManager(ctx context.Context, serverURLs []string, peerID string) *Manager {
	return &Manager{
		ctx:                     ctx,
		serverURLs:              serverURLs,
		peerID:                  peerID,
		tokenStore:              &relayAuth.TokenStore{},
		relayClients:            make(map[string]*RelayTrack),
		onDisconnectedListeners: make(map[string]*list.List),
	}
}

// Serve starts the manager. It will establish a connection to the relay server and start the relay cleanup loop for
// the unused relay connections. The manager will automatically reconnect to the relay server in case of disconnection.
func (m *Manager) Serve() error {
	if m.relayClient != nil {
		return fmt.Errorf("manager already serving")
	}
	log.Debugf("starting relay client manager with %v relay servers", m.serverURLs)

	totalServers := len(m.serverURLs)

	successChan := make(chan *Client, 1)
	errChan := make(chan error, len(m.serverURLs))

	ctx, cancel := context.WithTimeout(m.ctx, connectionTimeout)
	defer cancel()

	sem := make(chan struct{}, maxConcurrentServers)

	for _, url := range m.serverURLs {
		sem <- struct{}{}
		go func(url string) {
			defer func() { <-sem }()
			m.connect(m.ctx, url, successChan, errChan)
		}(url)
	}

	var errCount int

	for {
		select {
		case client := <-successChan:
			log.Infof("Successfully connected to relay server: %s", client.connectionURL)

			m.relayClient = client

			m.reconnectGuard = NewGuard(m.ctx, m.relayClient)
			m.relayClient.SetOnDisconnectListener(func() {
				m.onServerDisconnected(client.connectionURL)
			})
			m.startCleanupLoop()
			return nil
		case err := <-errChan:
			errCount++
			log.Warnf("Connection attempt failed: %v", err)
			if errCount == totalServers {
				return errors.New("failed to connect to any relay server: all attempts failed")
			}
		case <-ctx.Done():
			return fmt.Errorf("failed to connect to any relay server: %w", ctx.Err())
		}
	}
}

func (m *Manager) connect(ctx context.Context, serverURL string, successChan chan<- *Client, errChan chan<- error) {
	// TODO: abort the connection if another connection was successful
	relayClient := NewClient(ctx, serverURL, m.tokenStore, m.peerID)
	if err := relayClient.Connect(); err != nil {
		errChan <- fmt.Errorf("failed to connect to %s: %w", serverURL, err)
		return
	}

	select {
	case successChan <- relayClient:
		// This client was the first to connect successfully
	default:
		if err := relayClient.Close(); err != nil {
			log.Debugf("failed to close relay client: %s", err)
		}
	}
}

// OpenConn opens a connection to the given peer key. If the peer is on the same relay server, the connection will be
// established via the relay server. If the peer is on a different relay server, the manager will establish a new
// connection to the relay server. It returns back with a net.Conn what represent the remote peer connection.
func (m *Manager) OpenConn(serverAddress, peerKey string) (net.Conn, error) {
	if m.relayClient == nil {
		return nil, ErrRelayClientNotConnected
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

	return netConn, err
}

// AddCloseListener adds a listener to the given server instance address. The listener will be called if the connection
// closed.
func (m *Manager) AddCloseListener(serverAddress string, onClosedListener OnServerCloseListener) error {
	foreign, err := m.isForeignServer(serverAddress)
	if err != nil {
		return err
	}

	var listenerAddr string
	if foreign {
		listenerAddr = serverAddress
	} else {
		listenerAddr = m.relayClient.connectionURL
	}
	m.addListener(listenerAddr, onClosedListener)
	return nil
}

// RelayInstanceAddress returns the address of the permanent relay server. It could change if the network connection is
// lost. This address will be sent to the target peer to choose the common relay server for the communication.
func (m *Manager) RelayInstanceAddress() (string, error) {
	if m.relayClient == nil {
		return "", ErrRelayClientNotConnected
	}
	return m.relayClient.ServerInstanceURL()
}

// ServerURLs returns the addresses of the relay servers.
func (m *Manager) ServerURLs() []string {
	return m.serverURLs
}

// HasRelayAddress returns true if the manager is serving. With this method can check if the peer can communicate with
// Relay service.
func (m *Manager) HasRelayAddress() bool {
	return len(m.serverURLs) > 0
}

// UpdateToken updates the token in the token store.
func (m *Manager) UpdateToken(token *relayAuth.Token) error {
	return m.tokenStore.UpdateToken(token)
}

func (m *Manager) openConnVia(serverAddress, peerKey string) (net.Conn, error) {
	// check if already has a connection to the desired relay server
	m.relayClientsMutex.RLock()
	rt, ok := m.relayClients[serverAddress]
	if ok {
		rt.RLock()
		m.relayClientsMutex.RUnlock()
		defer rt.RUnlock()
		if rt.err != nil {
			return nil, rt.err
		}
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
		if rt.err != nil {
			return nil, rt.err
		}
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
		rt.err = err
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
	if serverAddress == m.relayClient.connectionURL {
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

func (m *Manager) addListener(serverAddress string, onClosedListener OnServerCloseListener) {
	m.listenerLock.Lock()
	defer m.listenerLock.Unlock()
	l, ok := m.onDisconnectedListeners[serverAddress]
	if !ok {
		l = list.New()
	}
	for e := l.Front(); e != nil; e = e.Next() {
		if reflect.ValueOf(e.Value).Pointer() == reflect.ValueOf(onClosedListener).Pointer() {
			return
		}
	}
	l.PushBack(onClosedListener)
	m.onDisconnectedListeners[serverAddress] = l
}

func (m *Manager) notifyOnDisconnectListeners(serverAddress string) {
	m.listenerLock.Lock()
	defer m.listenerLock.Unlock()

	l, ok := m.onDisconnectedListeners[serverAddress]
	if !ok {
		return
	}
	for e := l.Front(); e != nil; e = e.Next() {
		go e.Value.(OnServerCloseListener)()
	}
	delete(m.onDisconnectedListeners, serverAddress)
}
