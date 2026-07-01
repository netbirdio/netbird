package client

import (
	"container/list"
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	relayAuth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
)

var (
	relayCleanupInterval = 60 * time.Second
	keepUnusedServerTime = 5 * time.Second

	ErrRelayClientNotConnected = fmt.Errorf("relay client not connected")
)

type OnServerCloseListener func()

// ManagerOption configures a Manager at construction time.
type ManagerOption func(*Manager)

// RelayConnState is the connection state of a single relay server.
type RelayConnState struct {
	// URL is the server's instance address when connected, otherwise the
	// configured server URL.
	URL string
	// Transport is the negotiated transport, empty if not connected.
	Transport string
	// Err is set when the relay is not connected.
	Err error
}

type RelayServer struct {
	Addr string
	IP   netip.Addr
}

// WithMaxBackoffInterval caps the exponential backoff between reconnect
// attempts to the home relay. A non-positive value keeps the default.
func WithMaxBackoffInterval(d time.Duration) ManagerOption {
	return func(m *Manager) { m.maxBackoffInterval = d }
}

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

	foreign *ForeignRelaysStore

	onDisconnectedListeners map[string]*list.List
	onReconnectedListenerFn func()
	listenerLock            sync.Mutex

	mtu                uint16
	maxBackoffInterval time.Duration

	cleanupInterval      time.Duration
	keepUnusedServerTime time.Duration

	// transportFallback is shared across home and foreign relay clients so a
	// datagram-too-large failure makes that server avoid datagram-sized transports across reconnects.
	transportFallback *transportFallback
}

// NewManager creates a new manager instance.
// The serverURL address can be empty. In this case, the manager will not serve.
func NewManager(ctx context.Context, serverURLs []string, peerID string, mtu uint16, opts ...ManagerOption) *Manager {
	tokenStore := &relayAuth.TokenStore{}
	tf := newTransportFallback()

	m := &Manager{
		ctx:               ctx,
		peerID:            peerID,
		tokenStore:        tokenStore,
		mtu:               mtu,
		transportFallback: tf,
		serverPicker: &ServerPicker{
			TokenStore:        tokenStore,
			PeerID:            peerID,
			MTU:               mtu,
			ConnectionTimeout: defaultConnectionTimeout,
			TransportFallback: tf,
		},
		onDisconnectedListeners: make(map[string]*list.List),
		cleanupInterval:         relayCleanupInterval,
		keepUnusedServerTime:    keepUnusedServerTime,
	}
	for _, opt := range opts {
		opt(m)
	}
	m.foreign = NewForeignRelaysStore(ctx, tokenStore, peerID, mtu, tf, m.onServerDisconnected, m.keepUnusedServerTime)
	m.serverPicker.ServerURLs.Store(serverURLs)
	m.reconnectGuard = NewGuard(m.serverPicker, m.maxBackoffInterval)
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
		// record the initial failure so status shows the real reason before
		// the guard's first retry tick
		m.reconnectGuard.setLastError(err)
		go m.reconnectGuard.StartReconnectTrys(m.ctx, nil)
	} else {
		m.storeClient(client)
	}

	go m.listenGuardEvent(m.ctx)
	go m.startCleanupLoop()
	return err
}

func (m *Manager) OpenConn(ctx context.Context, remoteRelayServer RelayServer, peerKey string, preferForeign bool) (net.Conn, error) {
	m.relayClientMu.RLock()
	defer m.relayClientMu.RUnlock()

	if m.relayClient == nil {
		return nil, ErrRelayClientNotConnected
	}

	foreign, err := m.isForeignServer(remoteRelayServer.Addr)
	if err != nil {
		return nil, err
	}

	if !foreign {
		return m.relayClient.OpenConn(ctx, peerKey)
	}

	opener := NewFallbackOpener(m.relayClient, m.foreign)
	return opener.Run(ctx, peerKey, remoteRelayServer, preferForeign)
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

// RelayInstanceAddress returns the address and resolved IP of the permanent relay server. It could change if the
// network connection is lost. The address is sent to the target peer to choose the common relay server for the
// communication; the IP is sent alongside so remote peers can dial directly without their own DNS lookup. Both
// values are read under the same lock so they cannot diverge across a reconnection.
func (m *Manager) RelayInstanceAddress() (string, netip.Addr, error) {
	m.relayClientMu.RLock()
	defer m.relayClientMu.RUnlock()

	if m.relayClient == nil {
		return "", netip.Addr{}, ErrRelayClientNotConnected
	}
	addr, err := m.relayClient.ServerInstanceURL()
	if err != nil {
		return "", netip.Addr{}, err
	}
	return addr, m.relayClient.ConnectedIP(), nil
}

// ServerURLs returns the addresses of the relay servers.
func (m *Manager) ServerURLs() []string {
	return m.serverPicker.ServerURLs.Load().([]string)
}

// RelayConnectError returns the error from the most recent failed home relay
// reconnect attempt, or nil if the relay last connected successfully.
func (m *Manager) RelayConnectError() error {
	return m.reconnectGuard.LastError()
}

// RelayStates returns the connection state of the home relay and every foreign
// relay the manager currently tracks.
func (m *Manager) RelayStates() []RelayConnState {
	var states []RelayConnState

	m.relayClientMu.RLock()
	home := m.relayClient
	m.relayClientMu.RUnlock()
	if home != nil {
		st := relayConnState(home)
		// The home relay reconnects through the guard, so the real failure
		// reason lives there rather than on the (stale) client.
		if st.Err != nil {
			if gErr := m.reconnectGuard.LastError(); gErr != nil {
				st.Err = gErr
			}
		}
		states = append(states, st)
	}

	states = append(states, m.foreign.states()...)

	return states
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

func (m *Manager) onServerConnected() {
	m.listenerLock.Lock()
	defer m.listenerLock.Unlock()

	if m.onReconnectedListenerFn == nil {
		return
	}
	go m.onReconnectedListenerFn()
}

// onServerDisconnected handles relay disconnect events. For the home server it
// starts the reconnect guard. For foreign servers it evicts the now-dead client
// from the cache so the next OpenConn builds a fresh one instead of reusing a
// closed client.
func (m *Manager) onServerDisconnected(serverAddress string) {
	m.relayClientMu.Lock()
	isHome := m.relayClient != nil && serverAddress == m.relayClient.connectionURL
	if isHome {
		go func(client *Client) {
			m.reconnectGuard.StartReconnectTrys(m.ctx, client)
		}(m.relayClient)
	}
	m.relayClientMu.Unlock()

	if !isHome {
		m.foreign.evict(serverAddress)
	}

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
			m.foreign.cleanupUnused()
		}
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

func relayConnState(c *Client) RelayConnState {
	addr, err := c.ServerInstanceURL()
	if err != nil {
		return RelayConnState{URL: c.connectionURL, Err: err}
	}
	return RelayConnState{URL: addr, Transport: c.Transport()}
}
