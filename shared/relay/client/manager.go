package client

import (
	"container/list"
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	relayAuth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
)

const (
	defaultRelayCleanupInterval = 60 * time.Second
	defaultKeepUnusedServerTime = 5 * time.Second
	defaultMTU                  = 1280
	minMTU                      = 1280
	maxMTU                      = 65535
)

var (
	ErrRelayClientNotConnected = fmt.Errorf("relay client not connected")
)

// RelayTrack hold the relay clients for the foreign relay servers.
// With the mutex can ensure we can open new connection in case the relay connection has been established with
// the relay server.
type RelayTrack struct {
	sync.RWMutex
	relayClient *Client
	err         error
	created     time.Time
}

func NewRelayTrack() *RelayTrack {
	return &RelayTrack{
		created: time.Now(),
	}
}

type OnServerCloseListener func()

// Manager is a manager for the relay client instances. It establishes one persistent connection to the given relay URL
// and automatically reconnect to them in case disconnection.
// The manager also manage temporary relay connection. If a client wants to communicate with a client on a
// different relay server, the manager will establish a new connection to the relay server. The connection with these
// relay servers will be closed if there is no active connection. Periodically the manager will check if there is any
// unused relay connection and close it.
type Manager struct {
	ctx          context.Context
	peerID       string
	running      bool
	tokenStore   *relayAuth.TokenStore
	serverPicker *ServerPicker

	relayClient *Client
	// the guard logic can overwrite the relayClient variable, this mutex protect the usage of the variable
	relayClientMu  sync.RWMutex
	reconnectGuard *Guard

	relayClients      map[string]*RelayTrack
	relayClientsMutex sync.RWMutex

	onDisconnectedListeners map[string]*list.List
	onReconnectedListenerFn func()
	listenerLock            sync.Mutex

	cleanupInterval  time.Duration
	unusedServerTime time.Duration
	mtu              uint16
}

// ManagerOpts contains optional configuration for Manager
type ManagerOpts struct {
	// CleanupInterval is the interval for cleaning up unused relay connections.
	// If zero, defaults to defaultRelayCleanupInterval.
	CleanupInterval time.Duration
	// UnusedServerTime is the time to wait before closing unused relay connections.
	// If zero, defaults to defaultKeepUnusedServerTime.
	UnusedServerTime time.Duration
	// MTU is the maximum transmission unit for relay connections.
	// If zero, defaults to defaultMTU (1280).
	// Must be between minMTU (1280) and maxMTU (65535).
	MTU uint16
}

// NewManager creates a new manager instance.
// The serverURL address can be empty. In this case, the manager will not serve.
// Optional parameters can be configured using ManagerOpts. Pass nil to use default values.
func NewManager(ctx context.Context, serverURLs []string, peerID string, opts *ManagerOpts) *Manager {
	tokenStore := &relayAuth.TokenStore{}

	cleanupInterval := defaultRelayCleanupInterval
	unusedServerTime := defaultKeepUnusedServerTime
	mtu := uint16(defaultMTU)

	if opts != nil {
		if opts.CleanupInterval > 0 {
			cleanupInterval = opts.CleanupInterval
		}
		if opts.UnusedServerTime > 0 {
			unusedServerTime = opts.UnusedServerTime
		}
		if opts.MTU > 0 {
			if opts.MTU < minMTU {
				log.Warnf("MTU %d is below minimum %d, using minimum", opts.MTU, minMTU)
				mtu = minMTU
			} else if opts.MTU > maxMTU {
				log.Warnf("MTU %d exceeds maximum %d, using maximum", opts.MTU, maxMTU)
				mtu = maxMTU
			} else {
				mtu = opts.MTU
			}
		}
	}

	m := &Manager{
		ctx:        ctx,
		peerID:     peerID,
		tokenStore: tokenStore,
		mtu:        mtu,
		serverPicker: &ServerPicker{
			TokenStore:        tokenStore,
			PeerID:            peerID,
			MTU:               mtu,
			ConnectionTimeout: defaultConnectionTimeout,
		},
		relayClients:            make(map[string]*RelayTrack),
		onDisconnectedListeners: make(map[string]*list.List),
		cleanupInterval:         cleanupInterval,
		unusedServerTime:        unusedServerTime,
	}
	m.serverPicker.ServerURLs.Store(serverURLs)
	m.reconnectGuard = NewGuard(m.serverPicker)
	return m
}

// Serve starts the manager, attempting to establish a connection with the relay server.
// If the connection fails, it will keep trying to reconnect in the background.
// Additionally, it starts a cleanup loop to remove unused relay connections.
// The manager will automatically reconnect to the relay server in case of disconnection.
func (m *Manager) Serve() error {
	if m.running {
		return fmt.Errorf("manager already serving")
	}
	m.running = true
	log.Debugf("starting relay client manager with %v relay servers", m.serverPicker.ServerURLs.Load())

	client, err := m.serverPicker.PickServer(m.ctx)
	if err != nil {
		go m.reconnectGuard.StartReconnectTrys(m.ctx, nil)
	} else {
		m.storeClient(client)
	}

	go m.listenGuardEvent(m.ctx)
	go m.startCleanupLoop()
	return err
}

// OpenConn opens a connection to the given peer key. If the peer is on the same relay server, the connection will be
// established via the relay server. If the peer is on a different relay server, the manager will establish a new
// connection to the relay server. It returns back with a net.Conn what represent the remote peer connection.
func (m *Manager) OpenConn(ctx context.Context, serverAddress, peerKey string) (net.Conn, error) {
	m.relayClientMu.RLock()
	defer m.relayClientMu.RUnlock()

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
		netConn, err = m.relayClient.OpenConn(ctx, peerKey)
	} else {
		log.Debugf("open peer connection via foreign server: %s", serverAddress)
		netConn, err = m.openConnVia(ctx, serverAddress, peerKey)
	}
	if err != nil {
		return nil, err
	}

	return netConn, err
}

// Ready returns true if the home Relay client is connected to the relay server.
func (m *Manager) Ready() bool {
	m.relayClientMu.RLock()
	defer m.relayClientMu.RUnlock()

	if m.relayClient == nil {
		return false
	}
	return m.relayClient.Ready()
}

func (m *Manager) SetOnReconnectedListener(f func()) {
	m.listenerLock.Lock()
	defer m.listenerLock.Unlock()

	m.onReconnectedListenerFn = f
}

// AddCloseListener adds a listener to the given server instance address. The listener will be called if the connection
// closed.
func (m *Manager) AddCloseListener(serverAddress string, onClosedListener OnServerCloseListener) error {
	m.relayClientMu.RLock()
	defer m.relayClientMu.RUnlock()

	if m.relayClient == nil {
		return ErrRelayClientNotConnected
	}

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
	m.relayClientMu.RLock()
	defer m.relayClientMu.RUnlock()

	if m.relayClient == nil {
		return "", ErrRelayClientNotConnected
	}
	return m.relayClient.ServerInstanceURL()
}

// ServerURLs returns the addresses of the relay servers.
func (m *Manager) ServerURLs() []string {
	return m.serverPicker.ServerURLs.Load().([]string)
}

// HasRelayAddress returns true if the manager is serving. With this method can check if the peer can communicate with
// Relay service.
func (m *Manager) HasRelayAddress() bool {
	return len(m.serverPicker.ServerURLs.Load().([]string)) > 0
}

func (m *Manager) UpdateServerURLs(serverURLs []string) {
	log.Infof("update relay server URLs: %v", serverURLs)
	m.serverPicker.ServerURLs.Store(serverURLs)
}

// UpdateToken updates the token in the token store.
func (m *Manager) UpdateToken(token *relayAuth.Token) error {
	return m.tokenStore.UpdateToken(token)
}

func (m *Manager) openConnVia(ctx context.Context, serverAddress, peerKey string) (net.Conn, error) {
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
		return rt.relayClient.OpenConn(ctx, peerKey)
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
		return rt.relayClient.OpenConn(ctx, peerKey)
	}

	// create a new relay client and store it in the relayClients map
	rt = NewRelayTrack()
	rt.Lock()
	m.relayClients[serverAddress] = rt
	m.relayClientsMutex.Unlock()

	relayClient := NewClient(serverAddress, m.tokenStore, m.peerID, m.mtu)
	err := relayClient.Connect(m.ctx)
	if err != nil {
		rt.err = err
		rt.Unlock()
		m.relayClientsMutex.Lock()
		delete(m.relayClients, serverAddress)
		m.relayClientsMutex.Unlock()
		return nil, err
	}
	// if connection closed then delete the relay client from the list
	relayClient.SetOnDisconnectListener(m.onServerDisconnected)
	rt.relayClient = relayClient
	rt.Unlock()

	conn, err := relayClient.OpenConn(ctx, peerKey)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (m *Manager) onServerConnected() {
	m.listenerLock.Lock()
	defer m.listenerLock.Unlock()

	if m.onReconnectedListenerFn == nil {
		return
	}
	go m.onReconnectedListenerFn()
}

// onServerDisconnected start to reconnection for home server only
func (m *Manager) onServerDisconnected(serverAddress string) {
	m.relayClientMu.Lock()
	if serverAddress == m.relayClient.connectionURL {
		go func(client *Client) {
			m.reconnectGuard.StartReconnectTrys(m.ctx, client)
		}(m.relayClient)
	}
	m.relayClientMu.Unlock()

	m.notifyOnDisconnectListeners(serverAddress)
}

func (m *Manager) listenGuardEvent(ctx context.Context) {
	for {
		select {
		case <-m.reconnectGuard.OnReconnected:
			m.onServerConnected()
		case rc := <-m.reconnectGuard.OnNewRelayClient:
			m.storeClient(rc)
			m.onServerConnected()
		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) storeClient(client *Client) {
	m.relayClientMu.Lock()
	defer m.relayClientMu.Unlock()

	m.relayClient = client
	m.relayClient.SetOnDisconnectListener(m.onServerDisconnected)
}

func (m *Manager) isForeignServer(address string) (bool, error) {
	rAddr, err := m.relayClient.ServerInstanceURL()
	if err != nil {
		return false, fmt.Errorf("relay client not connected")
	}
	return rAddr != address, nil
}

func (m *Manager) startCleanupLoop() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanUpUnusedRelays()
		}
	}
}

func (m *Manager) cleanUpUnusedRelays() {
	m.relayClientsMutex.Lock()
	defer m.relayClientsMutex.Unlock()

	for addr, rt := range m.relayClients {
		rt.Lock()
		// if the connection failed to the server the relay client will be nil
		// but the instance will be kept in the relayClients until the next locking
		if rt.err != nil {
			rt.Unlock()
			continue
		}

		if time.Since(rt.created) <= m.unusedServerTime {
			rt.Unlock()
			continue
		}

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
