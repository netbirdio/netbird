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

// RelayTrack hold the relay clients for the foreign relay servers.
// With the mutex can ensure we can open new connection in case the relay connection has been established with
// the relay server.
type RelayTrack struct {
	sync.RWMutex
	relayClient *Client
	err         error
	created     time.Time
	// ready is closed once the dial started by openConnVia finishes (relayClient
	// or err is set). Callers reusing a track wait on this instead of the track
	// lock, so the dial never runs under rt.Lock.
	ready chan struct{}
}

func NewRelayTrack() *RelayTrack {
	return &RelayTrack{
		created: time.Now(),
		ready:   make(chan struct{}),
	}
}

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

	relayClients      map[string]*RelayTrack
	relayClientsMutex sync.RWMutex

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
		relayClients:            make(map[string]*RelayTrack),
		onDisconnectedListeners: make(map[string]*list.List),
		cleanupInterval:         relayCleanupInterval,
		keepUnusedServerTime:    keepUnusedServerTime,
	}
	for _, opt := range opts {
		opt(m)
	}
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

// OpenConn opens a connection to the given peer key. If the peer is on the same relay server, the connection will be
// established via the relay server. If the peer is on a different relay server, the manager will establish a new
// connection to the relay server. It returns back with a net.Conn what represent the remote peer connection.
//
// serverIP, when valid and serverAddress is foreign, is used as a dial target if the FQDN-based dial fails.
// Ignored for the local home-server path. TLS verification still uses the FQDN via SNI.
func (m *Manager) OpenConn(ctx context.Context, serverAddress, peerKey string, serverIP netip.Addr) (net.Conn, error) {
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
		netConn, err = m.openConnVia(ctx, serverAddress, peerKey, serverIP)
	}
	if err != nil {
		return nil, err
	}

	return netConn, err
}

// CloseConnByPeerKey closes an existing relay connection for the given peer key
// on the relay client associated with serverAddress, so that a subsequent
// OpenConn can create a fresh one.
func (m *Manager) CloseConnByPeerKey(serverAddress, peerKey string) {
	m.relayClientMu.RLock()
	homeClient := m.relayClient
	m.relayClientMu.RUnlock()

	if homeClient == nil {
		return
	}

	homeAddr, err := homeClient.ServerInstanceURL()
	if err == nil && homeAddr == serverAddress {
		homeClient.CloseConnByPeerKey(peerKey)
		return
	}

	m.relayClientsMutex.RLock()
	rt, ok := m.relayClients[serverAddress]
	m.relayClientsMutex.RUnlock()
	if !ok {
		return
	}

	// rt.relayClient is initialized in openConnVia under rt.Lock(); take rt.RLock()
	// to read it safely, then release before calling CloseConnByPeerKey to avoid
	// holding the track lock across a potentially blocking call.
	rt.RLock()
	relayClient := rt.relayClient
	rt.RUnlock()

	if relayClient != nil {
		relayClient.CloseConnByPeerKey(peerKey)
	}
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

	// Snapshot the tracks, then query each outside the map lock: a track can be
	// held by an in-progress Connect, and blocking on it must not stall other
	// relay operations.
	m.relayClientsMutex.RLock()
	tracks := make([]*RelayTrack, 0, len(m.relayClients))
	for _, rt := range m.relayClients {
		tracks = append(tracks, rt)
	}
	m.relayClientsMutex.RUnlock()

	// Only connected foreign relays carry state; a failed connect is evicted
	// immediately (openConnVia), so there is no error state to surface.
	for _, rt := range tracks {
		rt.RLock()
		rc := rt.relayClient
		rt.RUnlock()
		if rc != nil {
			states = append(states, relayConnState(rc))
		}
	}

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

func (m *Manager) openConnVia(ctx context.Context, serverAddress, peerKey string, serverIP netip.Addr) (net.Conn, error) {
	// check if already has a connection to the desired relay server
	m.relayClientsMutex.RLock()
	rt, ok := m.relayClients[serverAddress]
	m.relayClientsMutex.RUnlock()
	if ok {
		return m.openConnOnTrack(ctx, rt, peerKey)
	}

	// if not, establish a new connection but check it again (because changed the lock type) before starting the
	// connection
	m.relayClientsMutex.Lock()
	rt, ok = m.relayClients[serverAddress]
	if ok {
		m.relayClientsMutex.Unlock()
		return m.openConnOnTrack(ctx, rt, peerKey)
	}

	// Publish the track and release the map lock BEFORE dialing, so the dial does
	// not run under rt.Lock (which would block RelayStates and the cleanup loop
	// for the full dial). Concurrent callers find this track and wait on rt.ready.
	rt = NewRelayTrack()
	m.relayClients[serverAddress] = rt
	m.relayClientsMutex.Unlock()

	relayClient := NewClientWithServerIP(serverAddress, serverIP, m.tokenStore, m.peerID, m.mtu)
	relayClient.SetTransportFallback(m.transportFallback)
	err := relayClient.Connect(m.ctx)
	if err != nil {
		rt.Lock()
		rt.err = err
		rt.Unlock()
		close(rt.ready)
		m.relayClientsMutex.Lock()
		delete(m.relayClients, serverAddress)
		m.relayClientsMutex.Unlock()
		return nil, err
	}
	// if connection closed then delete the relay client from the list
	relayClient.SetOnDisconnectListener(m.onServerDisconnected)
	rt.Lock()
	rt.relayClient = relayClient
	rt.Unlock()
	close(rt.ready)

	return relayClient.OpenConn(ctx, peerKey)
}

// openConnOnTrack opens a peer connection through an existing relay track,
// waiting for the dial started by another openConnVia call to finish. It waits
// on rt.ready rather than the track lock, so it neither holds nor contends the
// track lock across the dial.
func (m *Manager) openConnOnTrack(ctx context.Context, rt *RelayTrack, peerKey string) (net.Conn, error) {
	select {
	case <-rt.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	rt.RLock()
	defer rt.RUnlock()
	if rt.err != nil {
		return nil, rt.err
	}
	if rt.relayClient == nil {
		return nil, ErrRelayClientNotConnected
	}
	return rt.relayClient.OpenConn(ctx, peerKey)
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
		m.evictForeignRelay(serverAddress)
	}

	m.notifyOnDisconnectListeners(serverAddress)
}

func (m *Manager) evictForeignRelay(serverAddress string) {
	m.relayClientsMutex.Lock()
	defer m.relayClientsMutex.Unlock()
	if _, ok := m.relayClients[serverAddress]; ok {
		delete(m.relayClients, serverAddress)
		log.Debugf("evicted disconnected foreign relay client: %s", serverAddress)
	}
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

		// dial still in progress (openConnVia publishes the track before Connect
		// completes and no longer holds rt.Lock during it), nothing to clean up.
		if rt.relayClient == nil {
			rt.Unlock()
			continue
		}

		if time.Since(rt.created) <= m.keepUnusedServerTime {
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

func relayConnState(c *Client) RelayConnState {
	addr, err := c.ServerInstanceURL()
	if err != nil {
		return RelayConnState{URL: c.connectionURL, Err: err}
	}
	return RelayConnState{URL: addr, Transport: c.Transport()}
}
