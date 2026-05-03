package peer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/internal/ingressgw"
	"github.com/netbirdio/netbird/client/internal/relay"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
)

const eventQueueSize = 10

type ResolvedDomainInfo struct {
	Prefixes     []netip.Prefix
	ParentDomain domain.Domain
}

type WGIfaceStatus interface {
	FullStats() (*configurer.Stats, error)
}

type EventListener interface {
	OnEvent(event *proto.SystemEvent)
}

// RouterState status for router peers. This contains relevant fields for route manager
type RouterState struct {
	Status  ConnStatus
	Relayed bool
	Latency time.Duration
}

// State contains the latest state of a peer
type State struct {
	Mux                        *sync.RWMutex
	IP                         string
	PubKey                     string
	FQDN                       string
	ConnStatus                 ConnStatus
	ConnStatusUpdate           time.Time
	Relayed                    bool
	LocalIceCandidateType      string
	RemoteIceCandidateType     string
	LocalIceCandidateEndpoint  string
	RemoteIceCandidateEndpoint string
	RelayServerAddress         string
	LastWireguardHandshake     time.Time
	BytesTx                    int64
	BytesRx                    int64
	Latency                    time.Duration
	RosenpassEnabled           bool
	SSHHostKey                 []byte
	routes                     map[string]struct{}
	// Phase 3 (#5989): ICE-backoff state for p2p-dynamic mode.
	IceBackoffFailures  int
	IceBackoffNextRetry time.Time
	IceBackoffSuspended bool
	// Phase 3.7i (#5989): true = peer is in d.peers; false = in d.offlinePeers.
	ServerOnline                     bool
	RemoteEffectiveConnectionMode    string
	RemoteConfiguredConnectionMode   string
	RemoteEffectiveRelayTimeoutSecs  uint32
	RemoteEffectiveP2PTimeoutSecs    uint32
	RemoteEffectiveP2PRetryMaxSecs   uint32
	RemoteConfiguredRelayTimeoutSecs uint32
	RemoteConfiguredP2PTimeoutSecs   uint32
	RemoteConfiguredP2PRetryMaxSecs  uint32
	RemoteGroups                     []string
	RemoteLastSeenAtServer           time.Time
	// Phase 3.7i (#5989): live mgmt-server-tracked liveness flag from
	// RemotePeerConfig.LiveOnline (= peer.Status.Connected on the server).
	// True = peer is currently heartbeating to mgmt; false = configured
	// but currently unreachable (hardware/network down). Used by the
	// counter widget to distinguish "online" from "offline" in the
	// user-intuitive sense, independent of the login-expiration split.
	RemoteLiveOnline bool
}

// AddRoute add a single route to routes map
func (s *State) AddRoute(network string) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if s.routes == nil {
		s.routes = make(map[string]struct{})
	}
	s.routes[network] = struct{}{}
}

// SetRoutes set state routes
func (s *State) SetRoutes(routes map[string]struct{}) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.routes = routes
}

// DeleteRoute removes a route from the network amp
func (s *State) DeleteRoute(network string) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	delete(s.routes, network)
}

// GetRoutes return routes map
func (s *State) GetRoutes() map[string]struct{} {
	s.Mux.RLock()
	defer s.Mux.RUnlock()
	return maps.Clone(s.routes)
}

// LocalPeerState contains the latest state of the local peer
type LocalPeerState struct {
	IP              string
	PubKey          string
	KernelInterface bool
	FQDN            string
	Routes          map[string]struct{}
}

// Clone returns a copy of the LocalPeerState
func (l LocalPeerState) Clone() LocalPeerState {
	l.Routes = maps.Clone(l.Routes)
	return l
}

// SignalState contains the latest state of a signal connection
type SignalState struct {
	URL       string
	Connected bool
	Error     error
}

// ManagementState contains the latest state of a management connection
type ManagementState struct {
	URL       string
	Connected bool
	Error     error
}

// RosenpassState contains the latest state of the Rosenpass configuration
type RosenpassState struct {
	Enabled    bool
	Permissive bool
}

// NSGroupState represents the status of a DNS server group, including associated domains,
// whether it's enabled, and the last error message encountered during probing.
type NSGroupState struct {
	ID      string
	Servers []netip.AddrPort
	Domains []string
	Enabled bool
	Error   error
}

// FullStatus contains the full state held by the Status instance
type FullStatus struct {
	Peers                 []State
	ManagementState       ManagementState
	SignalState           SignalState
	LocalPeerState        LocalPeerState
	RosenpassState        RosenpassState
	Relays                []relay.ProbeResult
	NSGroupStates         []NSGroupState
	NumOfForwardingRules  int
	LazyConnectionEnabled bool
	Events                []*proto.SystemEvent
	// Phase 3.7i (#5989): aggregate counters.
	ConfiguredPeersTotal  uint32
	ServerOnlinePeers     uint32
	P2PConnectedPeers     uint32
	RelayedConnectedPeers uint32
	IdleOnlinePeers       uint32
	ServerOfflinePeers    uint32
}

type StatusChangeSubscription struct {
	peerID     string
	id         string
	eventsChan chan map[string]RouterState
	ctx        context.Context
}

func newStatusChangeSubscription(ctx context.Context, peerID string) *StatusChangeSubscription {
	return &StatusChangeSubscription{
		ctx:    ctx,
		peerID: peerID,
		id:     uuid.New().String(),
		// it is a buffer for notifications to block less the status recorded
		eventsChan: make(chan map[string]RouterState, 8),
	}
}

func (s *StatusChangeSubscription) Events() chan map[string]RouterState {
	return s.eventsChan
}

// Status holds a state of peers, signal, management connections and relays
type Status struct {
	mux                   sync.Mutex
	peers                 map[string]State
	changeNotify          map[string]map[string]*StatusChangeSubscription // map[peerID]map[subscriptionID]*StatusChangeSubscription
	signalState           bool
	signalError           error
	managementState       bool
	managementError       error
	relayStates           []relay.ProbeResult
	localPeer             LocalPeerState
	offlinePeers          []State
	mgmAddress            string
	signalAddress         string
	notifier              *notifier
	rosenpassEnabled      bool
	rosenpassPermissive   bool
	nsGroupStates         []NSGroupState
	resolvedDomainsStates map[domain.Domain]ResolvedDomainInfo
	lazyConnectionEnabled bool

	// To reduce the number of notification invocation this bool will be true when need to call the notification
	// Some Peer actions mostly used by in a batch when the network map has been synchronized. In these type of events
	// set to true this variable and at the end of the processing we will reset it by the FinishPeerListModifications()
	peerListChangedForNotification bool

	relayMgr *relayClient.Manager

	eventMux     sync.RWMutex
	eventStreams map[string]chan *proto.SystemEvent
	eventQueue   *EventQueue

	ingressGwMgr *ingressgw.Manager

	routeIDLookup routeIDLookup
	wgIface       WGIfaceStatus

	// Phase 3.7i (#5989): per-peer state-change subscription. Set by
	// Engine; nil-checked everywhere. Fired AFTER releasing d.mux to
	// avoid holding the lock through user code.
	connStateListener func(pubkey string, st State)
}

// NewRecorder returns a new Status instance
func NewRecorder(mgmAddress string) *Status {
	return &Status{
		peers:                 make(map[string]State),
		changeNotify:          make(map[string]map[string]*StatusChangeSubscription),
		eventStreams:          make(map[string]chan *proto.SystemEvent),
		eventQueue:            NewEventQueue(eventQueueSize),
		offlinePeers:          make([]State, 0),
		notifier:              newNotifier(),
		mgmAddress:            mgmAddress,
		resolvedDomainsStates: map[domain.Domain]ResolvedDomainInfo{},
	}
}

// SetConnStateListener registers a callback that is called after each
// meaningful per-peer connection-state transition. The callback is
// invoked AFTER d.mux is released (Extract-Method pattern). Safe to
// call concurrently; may be set to nil to unregister.
// Phase 3.7i of #5989.
func (d *Status) SetConnStateListener(fn func(pubkey string, st State)) {
	d.mux.Lock()
	d.connStateListener = fn
	d.mux.Unlock()
}

// notifyConnStateChange returns a closure the caller invokes AFTER
// unlocking d.mux to deliver the state to the listener without holding
// the lock through user code. Caller must hold d.mux when calling this.
// Returns a no-op closure when no listener is registered.
func (d *Status) notifyConnStateChange(peerPubKey string, peerState State) func() {
	listener := d.connStateListener
	if listener == nil {
		return func() {}
	}
	stateCopy := peerState
	return func() { listener(peerPubKey, stateCopy) }
}

func (d *Status) SetRelayMgr(manager *relayClient.Manager) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.relayMgr = manager
}

func (d *Status) SetIngressGwMgr(ingressGwMgr *ingressgw.Manager) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.ingressGwMgr = ingressGwMgr
}

// ReplaceOfflinePeers replaces
func (d *Status) ReplaceOfflinePeers(replacement []State) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.offlinePeers = make([]State, len(replacement))
	copy(d.offlinePeers, replacement)

	// todo we should set to true in case if the list changed only
	d.peerListChangedForNotification = true
}

// AddPeer adds peer to Daemon status map
func (d *Status) AddPeer(peerPubKey string, fqdn string, ip string) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	_, ok := d.peers[peerPubKey]
	if ok {
		return errors.New("peer already exist")
	}
	d.peers[peerPubKey] = State{
		PubKey:     peerPubKey,
		IP:         ip,
		ConnStatus: StatusIdle,
		FQDN:       fqdn,
		Mux:        new(sync.RWMutex),
	}
	d.peerListChangedForNotification = true
	return nil
}

// GetPeer adds peer to Daemon status map
func (d *Status) GetPeer(peerPubKey string) (State, error) {
	d.mux.Lock()
	defer d.mux.Unlock()

	state, ok := d.peers[peerPubKey]
	if !ok {
		return State{}, configurer.ErrPeerNotFound
	}
	return state, nil
}

func (d *Status) PeerByIP(ip string) (string, bool) {
	d.mux.Lock()
	defer d.mux.Unlock()

	for _, state := range d.peers {
		if state.IP == ip {
			return state.FQDN, true
		}
	}
	return "", false
}

// RemovePeer removes peer from Daemon status map
func (d *Status) RemovePeer(peerPubKey string) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	_, ok := d.peers[peerPubKey]
	if !ok {
		return errors.New("no peer with to remove")
	}

	delete(d.peers, peerPubKey)
	d.peerListChangedForNotification = true
	return nil
}

// UpdatePeerState updates peer status
func (d *Status) UpdatePeerState(receivedState State) error {
	notifyFn, err := d.updatePeerStateLocked(receivedState)
	if err != nil {
		return err
	}
	notifyFn()
	return nil
}

func (d *Status) updatePeerStateLocked(receivedState State) (func(), error) {
	d.mux.Lock()

	peerState, ok := d.peers[receivedState.PubKey]
	if !ok {
		d.mux.Unlock()
		return func() {}, errors.New("peer doesn't exist")
	}

	oldState := peerState.ConnStatus

	if receivedState.ConnStatus != peerState.ConnStatus {
		peerState.ConnStatus = receivedState.ConnStatus
		peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
		peerState.Relayed = receivedState.Relayed
		peerState.LocalIceCandidateType = receivedState.LocalIceCandidateType
		peerState.RemoteIceCandidateType = receivedState.RemoteIceCandidateType
		peerState.LocalIceCandidateEndpoint = receivedState.LocalIceCandidateEndpoint
		peerState.RemoteIceCandidateEndpoint = receivedState.RemoteIceCandidateEndpoint
		peerState.RelayServerAddress = receivedState.RelayServerAddress
		peerState.RosenpassEnabled = receivedState.RosenpassEnabled
	}

	d.peers[receivedState.PubKey] = peerState

	notifyList := hasConnStatusChanged(oldState, receivedState.ConnStatus)
	// when we close the connection we will not notify the router manager
	notifyRouter := receivedState.ConnStatus == StatusIdle
	routerSnapshot := d.snapshotRouterPeersLocked(receivedState.PubKey, notifyRouter)
	numPeers := d.numOfPeers()

	d.mux.Unlock()

	if notifyList {
		d.notifier.peerListChanged(numPeers)
	}
	if notifyRouter {
		d.dispatchRouterPeers(receivedState.PubKey, routerSnapshot)
	}

	if hasConnStatusChanged(oldState, receivedState.ConnStatus) {
		return d.notifyConnStateChange(receivedState.PubKey, peerState), nil
	}
	return func() {}, nil
}

// UpdatePeerIceBackoff updates the ICE-backoff snapshot for a peer.
// Called by Conn.onICEFailed / onICEConnected so that the daemon
// status reflects current backoff state. Phase 3 of #5989.
func (d *Status) UpdatePeerIceBackoff(pubKey string, snap BackoffSnapshot) {
	d.mux.Lock()
	defer d.mux.Unlock()

	peerState, ok := d.peers[pubKey]
	if !ok {
		return
	}
	peerState.IceBackoffFailures = snap.Failures
	peerState.IceBackoffNextRetry = snap.NextRetry
	peerState.IceBackoffSuspended = snap.Suspended
	d.peers[pubKey] = peerState
}

// RemoteMeta is the slice of per-peer fields RemotePeerConfig populates.
// Phase 3.7i of #5989.
type RemoteMeta struct {
	EffectiveConnectionMode    string
	EffectiveRelayTimeoutSecs  uint32
	EffectiveP2PTimeoutSecs    uint32
	EffectiveP2PRetryMaxSecs   uint32
	ConfiguredConnectionMode   string
	ConfiguredRelayTimeoutSecs uint32
	ConfiguredP2PTimeoutSecs   uint32
	ConfiguredP2PRetryMaxSecs  uint32
	Groups                     []string
	LastSeenAtServer           time.Time
	LiveOnline                 bool
}

// UpdatePeerRemoteMeta sets the RemotePeerConfig-derived fields on the
// peer's State without touching ConnStatus or transport stats. Looks up
// the peer in both online (d.peers) and offline (d.offlinePeers) maps.
// Phase 3.7i of #5989.
func (d *Status) UpdatePeerRemoteMeta(pubKey string, meta RemoteMeta) error {
	d.mux.Lock()
	defer d.mux.Unlock()
	st, online := d.peers[pubKey]
	if online {
		st.RemoteEffectiveConnectionMode = meta.EffectiveConnectionMode
		st.RemoteConfiguredConnectionMode = meta.ConfiguredConnectionMode
		st.RemoteEffectiveRelayTimeoutSecs = meta.EffectiveRelayTimeoutSecs
		st.RemoteEffectiveP2PTimeoutSecs = meta.EffectiveP2PTimeoutSecs
		st.RemoteEffectiveP2PRetryMaxSecs = meta.EffectiveP2PRetryMaxSecs
		st.RemoteConfiguredRelayTimeoutSecs = meta.ConfiguredRelayTimeoutSecs
		st.RemoteConfiguredP2PTimeoutSecs = meta.ConfiguredP2PTimeoutSecs
		st.RemoteConfiguredP2PRetryMaxSecs = meta.ConfiguredP2PRetryMaxSecs
		st.RemoteGroups = meta.Groups
		st.RemoteLastSeenAtServer = meta.LastSeenAtServer
		st.RemoteLiveOnline = meta.LiveOnline
		d.peers[pubKey] = st
		return nil
	}
	for i := range d.offlinePeers {
		if d.offlinePeers[i].PubKey == pubKey {
			d.offlinePeers[i].RemoteEffectiveConnectionMode = meta.EffectiveConnectionMode
			d.offlinePeers[i].RemoteConfiguredConnectionMode = meta.ConfiguredConnectionMode
			d.offlinePeers[i].RemoteEffectiveRelayTimeoutSecs = meta.EffectiveRelayTimeoutSecs
			d.offlinePeers[i].RemoteEffectiveP2PTimeoutSecs = meta.EffectiveP2PTimeoutSecs
			d.offlinePeers[i].RemoteEffectiveP2PRetryMaxSecs = meta.EffectiveP2PRetryMaxSecs
			d.offlinePeers[i].RemoteConfiguredRelayTimeoutSecs = meta.ConfiguredRelayTimeoutSecs
			d.offlinePeers[i].RemoteConfiguredP2PTimeoutSecs = meta.ConfiguredP2PTimeoutSecs
			d.offlinePeers[i].RemoteConfiguredP2PRetryMaxSecs = meta.ConfiguredP2PRetryMaxSecs
			d.offlinePeers[i].RemoteGroups = meta.Groups
			d.offlinePeers[i].RemoteLastSeenAtServer = meta.LastSeenAtServer
			d.offlinePeers[i].RemoteLiveOnline = meta.LiveOnline
			return nil
		}
	}
	return fmt.Errorf("peer %s not found in either map", pubKey)
}

// TimestampOrZero converts a *timestamppb.Timestamp to time.Time,
// returning zero-time when the proto pointer is nil. Used by engine.go
// (Task 3.3) when populating RemoteMeta from RemotePeerConfig where
// last_seen_at_server may be unset for peers that pre-date Phase 3.7i.
// Phase 3.7i of #5989.
func TimestampOrZero(t *timestamppb.Timestamp) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.AsTime()
}

func (d *Status) AddPeerStateRoute(peer string, route string, resourceId route.ResID) error {
	d.mux.Lock()

	peerState, ok := d.peers[peer]
	if !ok {
		d.mux.Unlock()
		return errors.New("peer doesn't exist")
	}

	peerState.AddRoute(route)
	d.peers[peer] = peerState

	pref, err := netip.ParsePrefix(route)
	if err == nil {
		d.routeIDLookup.AddRemoteRouteID(resourceId, pref)
	}

	numPeers := d.numOfPeers()
	d.mux.Unlock()

	// todo: consider to make sense of this notification or not
	d.notifier.peerListChanged(numPeers)
	return nil
}

func (d *Status) RemovePeerStateRoute(peer string, route string) error {
	d.mux.Lock()

	peerState, ok := d.peers[peer]
	if !ok {
		d.mux.Unlock()
		return errors.New("peer doesn't exist")
	}

	peerState.DeleteRoute(route)
	d.peers[peer] = peerState

	pref, err := netip.ParsePrefix(route)
	if err == nil {
		d.routeIDLookup.RemoveRemoteRouteID(pref)
	}

	numPeers := d.numOfPeers()
	d.mux.Unlock()

	// todo: consider to make sense of this notification or not
	d.notifier.peerListChanged(numPeers)
	return nil
}

// CheckRoutes checks if the source and destination addresses are within the same route
// and returns the resource ID of the route that contains the addresses
func (d *Status) CheckRoutes(ip netip.Addr) ([]byte, bool) {
	if d == nil {
		return nil, false
	}
	resId, isExitNode := d.routeIDLookup.Lookup(ip)
	return []byte(resId), isExitNode
}

func (d *Status) UpdatePeerICEState(receivedState State) error {
	notifyFn, err := d.updatePeerICEStateLocked(receivedState)
	if err != nil {
		return err
	}
	notifyFn()
	return nil
}

func (d *Status) updatePeerICEStateLocked(receivedState State) (func(), error) {
	d.mux.Lock()

	peerState, ok := d.peers[receivedState.PubKey]
	if !ok {
		d.mux.Unlock()
		return func() {}, errors.New("peer doesn't exist")
	}

	oldState := peerState.ConnStatus
	oldIsRelayed := peerState.Relayed

	peerState.ConnStatus = receivedState.ConnStatus
	peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
	peerState.Relayed = receivedState.Relayed
	peerState.LocalIceCandidateType = receivedState.LocalIceCandidateType
	peerState.RemoteIceCandidateType = receivedState.RemoteIceCandidateType
	peerState.LocalIceCandidateEndpoint = receivedState.LocalIceCandidateEndpoint
	peerState.RemoteIceCandidateEndpoint = receivedState.RemoteIceCandidateEndpoint
	peerState.RosenpassEnabled = receivedState.RosenpassEnabled

	d.peers[receivedState.PubKey] = peerState

	notifyList := hasConnStatusChanged(oldState, receivedState.ConnStatus)
	notifyRouter := hasStatusOrRelayedChange(oldState, receivedState.ConnStatus, oldIsRelayed, receivedState.Relayed)
	routerSnapshot := d.snapshotRouterPeersLocked(receivedState.PubKey, notifyRouter)
	numPeers := d.numOfPeers()

	d.mux.Unlock()

	if notifyList {
		d.notifier.peerListChanged(numPeers)
	}
	if notifyRouter {
		d.dispatchRouterPeers(receivedState.PubKey, routerSnapshot)
	}

	if hasStatusOrRelayedChange(oldState, receivedState.ConnStatus, oldIsRelayed, receivedState.Relayed) {
		return d.notifyConnStateChange(receivedState.PubKey, peerState), nil
	}
	return func() {}, nil
}

func (d *Status) UpdatePeerRelayedState(receivedState State) error {
	notifyFn, err := d.updatePeerRelayedStateLocked(receivedState)
	if err != nil {
		return err
	}
	notifyFn()
	return nil
}

func (d *Status) updatePeerRelayedStateLocked(receivedState State) (func(), error) {
	d.mux.Lock()

	peerState, ok := d.peers[receivedState.PubKey]
	if !ok {
		d.mux.Unlock()
		return func() {}, errors.New("peer doesn't exist")
	}

	oldState := peerState.ConnStatus
	oldIsRelayed := peerState.Relayed

	peerState.ConnStatus = receivedState.ConnStatus
	peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
	peerState.Relayed = receivedState.Relayed
	peerState.RelayServerAddress = receivedState.RelayServerAddress
	peerState.RosenpassEnabled = receivedState.RosenpassEnabled

	d.peers[receivedState.PubKey] = peerState

	notifyList := hasConnStatusChanged(oldState, receivedState.ConnStatus)
	notifyRouter := hasStatusOrRelayedChange(oldState, receivedState.ConnStatus, oldIsRelayed, receivedState.Relayed)
	routerSnapshot := d.snapshotRouterPeersLocked(receivedState.PubKey, notifyRouter)
	numPeers := d.numOfPeers()

	d.mux.Unlock()

	if notifyList {
		d.notifier.peerListChanged(numPeers)
	}
	if notifyRouter {
		d.dispatchRouterPeers(receivedState.PubKey, routerSnapshot)
	}

	if hasStatusOrRelayedChange(oldState, receivedState.ConnStatus, oldIsRelayed, receivedState.Relayed) {
		return d.notifyConnStateChange(receivedState.PubKey, peerState), nil
	}
	return func() {}, nil
}

func (d *Status) UpdatePeerRelayedStateToDisconnected(receivedState State) error {
	notifyFn, err := d.updatePeerRelayedStateToDisconnectedLocked(receivedState)
	if err != nil {
		return err
	}
	notifyFn()
	return nil
}

func (d *Status) updatePeerRelayedStateToDisconnectedLocked(receivedState State) (func(), error) {
	d.mux.Lock()

	peerState, ok := d.peers[receivedState.PubKey]
	if !ok {
		d.mux.Unlock()
		return func() {}, errors.New("peer doesn't exist")
	}

	oldState := peerState.ConnStatus
	oldIsRelayed := peerState.Relayed

	peerState.ConnStatus = receivedState.ConnStatus
	peerState.Relayed = receivedState.Relayed
	peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
	peerState.RelayServerAddress = ""

	d.peers[receivedState.PubKey] = peerState

	notifyList := hasConnStatusChanged(oldState, receivedState.ConnStatus)
	notifyRouter := hasStatusOrRelayedChange(oldState, receivedState.ConnStatus, oldIsRelayed, receivedState.Relayed)
	routerSnapshot := d.snapshotRouterPeersLocked(receivedState.PubKey, notifyRouter)
	numPeers := d.numOfPeers()

	d.mux.Unlock()

	if notifyList {
		d.notifier.peerListChanged(numPeers)
	}
	if notifyRouter {
		d.dispatchRouterPeers(receivedState.PubKey, routerSnapshot)
	}

	if hasStatusOrRelayedChange(oldState, receivedState.ConnStatus, oldIsRelayed, receivedState.Relayed) {
		return d.notifyConnStateChange(receivedState.PubKey, peerState), nil
	}
	return func() {}, nil
}

func (d *Status) UpdatePeerICEStateToDisconnected(receivedState State) error {
	notifyFn, err := d.updatePeerICEStateToDisconnectedLocked(receivedState)
	if err != nil {
		return err
	}
	notifyFn()
	return nil
}

func (d *Status) updatePeerICEStateToDisconnectedLocked(receivedState State) (func(), error) {
	d.mux.Lock()

	peerState, ok := d.peers[receivedState.PubKey]
	if !ok {
		d.mux.Unlock()
		return func() {}, errors.New("peer doesn't exist")
	}

	oldState := peerState.ConnStatus
	oldIsRelayed := peerState.Relayed

	peerState.ConnStatus = receivedState.ConnStatus
	peerState.Relayed = receivedState.Relayed
	peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
	peerState.LocalIceCandidateType = receivedState.LocalIceCandidateType
	peerState.RemoteIceCandidateType = receivedState.RemoteIceCandidateType
	peerState.LocalIceCandidateEndpoint = receivedState.LocalIceCandidateEndpoint
	peerState.RemoteIceCandidateEndpoint = receivedState.RemoteIceCandidateEndpoint

	d.peers[receivedState.PubKey] = peerState

	notifyList := hasConnStatusChanged(oldState, receivedState.ConnStatus)
	notifyRouter := hasStatusOrRelayedChange(oldState, receivedState.ConnStatus, oldIsRelayed, receivedState.Relayed)
	routerSnapshot := d.snapshotRouterPeersLocked(receivedState.PubKey, notifyRouter)
	numPeers := d.numOfPeers()

	d.mux.Unlock()

	if notifyList {
		d.notifier.peerListChanged(numPeers)
	}
	if notifyRouter {
		d.dispatchRouterPeers(receivedState.PubKey, routerSnapshot)
	}

	if hasStatusOrRelayedChange(oldState, receivedState.ConnStatus, oldIsRelayed, receivedState.Relayed) {
		return d.notifyConnStateChange(receivedState.PubKey, peerState), nil
	}
	return func() {}, nil
}

// UpdateWireGuardPeerState updates the WireGuard bits of the peer state
func (d *Status) UpdateWireGuardPeerState(pubKey string, wgStats configurer.WGStats) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	peerState, ok := d.peers[pubKey]
	if !ok {
		return errors.New("peer doesn't exist")
	}

	peerState.LastWireguardHandshake = wgStats.LastHandshake
	peerState.BytesRx = wgStats.RxBytes
	peerState.BytesTx = wgStats.TxBytes

	d.peers[pubKey] = peerState

	return nil
}

func hasStatusOrRelayedChange(oldConnStatus, newConnStatus ConnStatus, oldRelayed, newRelayed bool) bool {
	return oldRelayed != newRelayed || hasConnStatusChanged(newConnStatus, oldConnStatus)
}

func hasConnStatusChanged(oldStatus, newStatus ConnStatus) bool {
	return newStatus != oldStatus
}

// UpdatePeerFQDN update peer's state fqdn only
func (d *Status) UpdatePeerFQDN(peerPubKey, fqdn string) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	peerState, ok := d.peers[peerPubKey]
	if !ok {
		return errors.New("peer doesn't exist")
	}

	peerState.FQDN = fqdn
	d.peers[peerPubKey] = peerState

	return nil
}

// UpdatePeerSSHHostKey updates peer's SSH host key
func (d *Status) UpdatePeerSSHHostKey(peerPubKey string, sshHostKey []byte) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	peerState, ok := d.peers[peerPubKey]
	if !ok {
		return errors.New("peer doesn't exist")
	}

	peerState.SSHHostKey = sshHostKey
	d.peers[peerPubKey] = peerState

	return nil
}

// FinishPeerListModifications this event invoke the notification
func (d *Status) FinishPeerListModifications() {
	d.mux.Lock()

	if !d.peerListChangedForNotification {
		d.mux.Unlock()
		return
	}
	d.peerListChangedForNotification = false

	numPeers := d.numOfPeers()

	// snapshot per-peer router state to deliver after the lock is released
	type routerDispatch struct {
		peerID   string
		snapshot map[string]RouterState
	}
	dispatches := make([]routerDispatch, 0, len(d.peers))
	for key := range d.peers {
		snapshot := d.snapshotRouterPeersLocked(key, true)
		if snapshot != nil {
			dispatches = append(dispatches, routerDispatch{peerID: key, snapshot: snapshot})
		}
	}

	d.mux.Unlock()

	d.notifier.peerListChanged(numPeers)
	for _, rd := range dispatches {
		d.dispatchRouterPeers(rd.peerID, rd.snapshot)
	}
}

func (d *Status) SubscribeToPeerStateChanges(ctx context.Context, peerID string) *StatusChangeSubscription {
	d.mux.Lock()
	defer d.mux.Unlock()

	sub := newStatusChangeSubscription(ctx, peerID)
	if _, ok := d.changeNotify[peerID]; !ok {
		d.changeNotify[peerID] = make(map[string]*StatusChangeSubscription)
	}
	d.changeNotify[peerID][sub.id] = sub

	return sub
}

func (d *Status) UnsubscribePeerStateChanges(subscription *StatusChangeSubscription) {
	d.mux.Lock()
	defer d.mux.Unlock()

	if subscription == nil {
		return
	}

	channels, ok := d.changeNotify[subscription.peerID]
	if !ok {
		return
	}

	sub, exists := channels[subscription.id]
	if !exists {
		return
	}

	delete(channels, subscription.id)
	if len(channels) == 0 {
		delete(d.changeNotify, sub.peerID)
	}
}

// GetLocalPeerState returns the local peer state
func (d *Status) GetLocalPeerState() LocalPeerState {
	d.mux.Lock()
	defer d.mux.Unlock()
	return d.localPeer.Clone()
}

// UpdateLocalPeerState updates local peer status
func (d *Status) UpdateLocalPeerState(localPeerState LocalPeerState) {
	d.mux.Lock()
	d.localPeer = localPeerState
	fqdn := d.localPeer.FQDN
	ip := d.localPeer.IP
	d.mux.Unlock()

	d.notifier.localAddressChanged(fqdn, ip)
}

// AddLocalPeerStateRoute adds a route to the local peer state
func (d *Status) AddLocalPeerStateRoute(route string, resourceId route.ResID) {
	d.mux.Lock()
	defer d.mux.Unlock()

	pref, err := netip.ParsePrefix(route)
	if err == nil {
		d.routeIDLookup.AddLocalRouteID(resourceId, pref)
	}

	if d.localPeer.Routes == nil {
		d.localPeer.Routes = map[string]struct{}{}
	}

	d.localPeer.Routes[route] = struct{}{}
}

// RemoveLocalPeerStateRoute removes a route from the local peer state
func (d *Status) RemoveLocalPeerStateRoute(route string) {
	d.mux.Lock()
	defer d.mux.Unlock()

	pref, err := netip.ParsePrefix(route)
	if err == nil {
		d.routeIDLookup.RemoveLocalRouteID(pref)
	}

	delete(d.localPeer.Routes, route)
}

// AddResolvedIPLookupEntry adds a resolved IP lookup entry
func (d *Status) AddResolvedIPLookupEntry(prefix netip.Prefix, resourceId route.ResID) {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.routeIDLookup.AddResolvedIP(resourceId, prefix)
}

// RemoveResolvedIPLookupEntry removes a resolved IP lookup entry
func (d *Status) RemoveResolvedIPLookupEntry(route string) {
	d.mux.Lock()
	defer d.mux.Unlock()

	pref, err := netip.ParsePrefix(route)
	if err == nil {
		d.routeIDLookup.RemoveResolvedIP(pref)
	}
}

// CleanLocalPeerStateRoutes cleans all routes from the local peer state
func (d *Status) CleanLocalPeerStateRoutes() {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.localPeer.Routes = map[string]struct{}{}
}

// CleanLocalPeerState cleans local peer status
func (d *Status) CleanLocalPeerState() {
	d.mux.Lock()
	d.localPeer = LocalPeerState{}
	fqdn := d.localPeer.FQDN
	ip := d.localPeer.IP
	d.mux.Unlock()

	d.notifier.localAddressChanged(fqdn, ip)
}

// MarkManagementDisconnected sets ManagementState to disconnected
func (d *Status) MarkManagementDisconnected(err error) {
	d.mux.Lock()
	d.managementState = false
	d.managementError = err
	mgm := d.managementState
	sig := d.signalState
	d.mux.Unlock()

	d.notifier.updateServerStates(mgm, sig)
}

// MarkManagementConnected sets ManagementState to connected
func (d *Status) MarkManagementConnected() {
	d.mux.Lock()
	d.managementState = true
	d.managementError = nil
	mgm := d.managementState
	sig := d.signalState
	d.mux.Unlock()

	d.notifier.updateServerStates(mgm, sig)
}

// UpdateSignalAddress update the address of the signal server
func (d *Status) UpdateSignalAddress(signalURL string) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.signalAddress = signalURL
}

// UpdateManagementAddress update the address of the management server
func (d *Status) UpdateManagementAddress(mgmAddress string) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.mgmAddress = mgmAddress
}

// UpdateRosenpass update the Rosenpass configuration
func (d *Status) UpdateRosenpass(rosenpassEnabled, rosenpassPermissive bool) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.rosenpassPermissive = rosenpassPermissive
	d.rosenpassEnabled = rosenpassEnabled
}

func (d *Status) UpdateLazyConnection(enabled bool) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.lazyConnectionEnabled = enabled
}

// MarkSignalDisconnected sets SignalState to disconnected
func (d *Status) MarkSignalDisconnected(err error) {
	d.mux.Lock()
	d.signalState = false
	d.signalError = err
	mgm := d.managementState
	sig := d.signalState
	d.mux.Unlock()

	d.notifier.updateServerStates(mgm, sig)
}

// MarkSignalConnected sets SignalState to connected
func (d *Status) MarkSignalConnected() {
	d.mux.Lock()
	d.signalState = true
	d.signalError = nil
	mgm := d.managementState
	sig := d.signalState
	d.mux.Unlock()

	d.notifier.updateServerStates(mgm, sig)
}

func (d *Status) UpdateRelayStates(relayResults []relay.ProbeResult) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.relayStates = relayResults
}

func (d *Status) UpdateDNSStates(dnsStates []NSGroupState) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.nsGroupStates = dnsStates
}

func (d *Status) UpdateResolvedDomainsStates(originalDomain domain.Domain, resolvedDomain domain.Domain, prefixes []netip.Prefix, resourceId route.ResID) {
	d.mux.Lock()
	defer d.mux.Unlock()

	// Store both the original domain pattern and resolved domain
	d.resolvedDomainsStates[resolvedDomain] = ResolvedDomainInfo{
		Prefixes:     prefixes,
		ParentDomain: originalDomain,
	}

	for _, prefix := range prefixes {
		d.routeIDLookup.AddResolvedIP(resourceId, prefix)
	}
}

func (d *Status) DeleteResolvedDomainsStates(domain domain.Domain) {
	d.mux.Lock()
	defer d.mux.Unlock()

	// Remove all entries that have this domain as their parent
	for k, v := range d.resolvedDomainsStates {
		if v.ParentDomain == domain {
			delete(d.resolvedDomainsStates, k)

			for _, prefix := range v.Prefixes {
				d.routeIDLookup.RemoveResolvedIP(prefix)
			}
		}
	}
}

func (d *Status) GetRosenpassState() RosenpassState {
	d.mux.Lock()
	defer d.mux.Unlock()
	return RosenpassState{
		d.rosenpassEnabled,
		d.rosenpassPermissive,
	}
}

func (d *Status) GetLazyConnection() bool {
	d.mux.Lock()
	defer d.mux.Unlock()
	return d.lazyConnectionEnabled
}

func (d *Status) GetManagementState() ManagementState {
	d.mux.Lock()
	defer d.mux.Unlock()
	return ManagementState{
		d.mgmAddress,
		d.managementState,
		d.managementError,
	}
}

func (d *Status) UpdateLatency(pubKey string, latency time.Duration) error {
	if latency <= 0 {
		return nil
	}

	d.mux.Lock()
	defer d.mux.Unlock()
	peerState, ok := d.peers[pubKey]
	if !ok {
		return errors.New("peer doesn't exist")
	}
	peerState.Latency = latency
	d.peers[pubKey] = peerState
	return nil
}

// IsLoginRequired determines if a peer's login has expired.
func (d *Status) IsLoginRequired() bool {
	d.mux.Lock()
	defer d.mux.Unlock()

	// if peer is connected to the management then login is not expired
	if d.managementState {
		return false
	}

	s, ok := gstatus.FromError(d.managementError)
	if ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
		return true
	}
	return false
}

func (d *Status) GetSignalState() SignalState {
	d.mux.Lock()
	defer d.mux.Unlock()
	return SignalState{
		d.signalAddress,
		d.signalState,
		d.signalError,
	}
}

// GetRelayStates returns the stun/turn/permanent relay states
func (d *Status) GetRelayStates() []relay.ProbeResult {
	d.mux.Lock()
	defer d.mux.Unlock()
	if d.relayMgr == nil {
		return d.relayStates
	}

	// extend the list of stun, turn servers with relay address
	relayStates := slices.Clone(d.relayStates)

	// if the server connection is not established then we will use the general address
	// in case of connection we will use the instance specific address
	instanceAddr, _, err := d.relayMgr.RelayInstanceAddress()
	if err != nil {
		// TODO add their status
		for _, r := range d.relayMgr.ServerURLs() {
			relayStates = append(relayStates, relay.ProbeResult{
				URI: r,
				Err: err,
			})
		}
		return relayStates
	}

	relayState := relay.ProbeResult{
		URI: instanceAddr,
	}
	return append(relayStates, relayState)
}

func (d *Status) ForwardingRules() []firewall.ForwardRule {
	d.mux.Lock()
	defer d.mux.Unlock()
	if d.ingressGwMgr == nil {
		return nil
	}

	return d.ingressGwMgr.Rules()
}

func (d *Status) GetDNSStates() []NSGroupState {
	d.mux.Lock()
	defer d.mux.Unlock()

	// shallow copy is good enough, as slices fields are currently not updated
	return slices.Clone(d.nsGroupStates)
}

func (d *Status) GetResolvedDomainsStates() map[domain.Domain]ResolvedDomainInfo {
	d.mux.Lock()
	defer d.mux.Unlock()
	return maps.Clone(d.resolvedDomainsStates)
}

// GetFullStatus gets full status
func (d *Status) GetFullStatus() FullStatus {
	fullStatus := FullStatus{
		ManagementState:       d.GetManagementState(),
		SignalState:           d.GetSignalState(),
		Relays:                d.GetRelayStates(),
		RosenpassState:        d.GetRosenpassState(),
		NSGroupStates:         d.GetDNSStates(),
		NumOfForwardingRules:  len(d.ForwardingRules()),
		LazyConnectionEnabled: d.GetLazyConnection(),
	}

	d.mux.Lock()
	defer d.mux.Unlock()

	fullStatus.LocalPeerState = d.localPeer

	var p2p, relayed, idle, offline uint32

	// Phase 3.7i (#5989) counter semantics:
	//   ServerOnline := peer.Status.Connected on the management server
	//                   (RemotePeerConfig.live_online → State.RemoteLiveOnline)
	//   Offline      := configured but NOT live (heartbeat is stale OR
	//                   login expired). For login-expired peers, the
	//                   daemon already places them in d.offlinePeers via
	//                   updateOfflinePeers; the rest live in d.peers
	//                   regardless of their live status, so we additionally
	//                   check RemoteLiveOnline.
	//
	// Backward-compat fallback: if the management server pre-dates
	// Phase 3.7i, RemoteLastSeenAtServer is zero AND RemoteLiveOnline is
	// false (zero values for the never-populated proto fields). In that
	// case we cannot tell live vs not — fall back to legacy behaviour
	// (assume online). Only treat a peer as offline when LastSeen IS set
	// AND LiveOnline is explicitly false.
	for _, status := range d.peers {
		mgmtKnowsLiveness := !status.RemoteLastSeenAtServer.IsZero()
		isLive := status.RemoteLiveOnline || !mgmtKnowsLiveness
		if isLive {
			status.ServerOnline = true
			switch {
			case status.ConnStatus == StatusConnected && !status.Relayed:
				p2p++
			case status.ConnStatus == StatusConnected && status.Relayed:
				relayed++
			default:
				idle++
			}
		} else {
			status.ServerOnline = false
			offline++
		}
		fullStatus.Peers = append(fullStatus.Peers, status)
	}
	for _, status := range d.offlinePeers {
		// Login-expired peers are always offline.
		status.ServerOnline = false
		offline++
		fullStatus.Peers = append(fullStatus.Peers, status)
	}

	fullStatus.P2PConnectedPeers = p2p
	fullStatus.RelayedConnectedPeers = relayed
	fullStatus.IdleOnlinePeers = idle
	fullStatus.ServerOfflinePeers = offline
	fullStatus.ServerOnlinePeers = p2p + relayed + idle
	fullStatus.ConfiguredPeersTotal = fullStatus.ServerOnlinePeers + offline

	fullStatus.Events = d.GetEventHistory()
	return fullStatus
}

// ClientStart will notify all listeners about the new service state
func (d *Status) ClientStart() {
	d.notifier.clientStart()
}

// ClientStop will notify all listeners about the new service state
func (d *Status) ClientStop() {
	d.notifier.clientStop()
}

// ClientTeardown will notify all listeners about the service is under teardown
func (d *Status) ClientTeardown() {
	d.notifier.clientTearDown()
}

// SetConnectionListener set a listener to the notifier
func (d *Status) SetConnectionListener(listener Listener) {
	d.notifier.setListener(listener)
}

// RemoveConnectionListener remove the listener from the notifier
func (d *Status) RemoveConnectionListener() {
	d.notifier.removeListener()
}

// snapshotRouterPeersLocked builds the RouterState map for a peer's subscribers.
// Caller MUST hold d.mux. Returns nil when there are no subscribers for peerID
// or when notify is false. The snapshot is consumed later by dispatchRouterPeers
// outside the lock so the channel send cannot stall any d.mux holder.
func (d *Status) snapshotRouterPeersLocked(peerID string, notify bool) map[string]RouterState {
	if !notify {
		return nil
	}
	if _, ok := d.changeNotify[peerID]; !ok {
		return nil
	}
	routerPeers := make(map[string]RouterState, len(d.changeNotify))
	for pid := range d.changeNotify {
		s, ok := d.peers[pid]
		if !ok {
			log.Warnf("router peer not found in peers list: %s", pid)
			continue
		}
		routerPeers[pid] = RouterState{
			Status:  s.ConnStatus,
			Relayed: s.Relayed,
			Latency: s.Latency,
		}
	}
	return routerPeers
}

// dispatchRouterPeers delivers a previously snapshotted router-state map to
// the peer's subscribers. Caller MUST NOT hold d.mux. The method takes a
// fresh, short read of d.changeNotify under the lock to grab subscriber
// channels, then sends outside the lock so a slow consumer cannot block other
// d.mux holders. The send itself stays blocking (only short-circuited by the
// subscriber's context) so peer state transitions are not silently dropped.
func (d *Status) dispatchRouterPeers(peerID string, routerPeers map[string]RouterState) {
	if routerPeers == nil {
		return
	}

	d.mux.Lock()
	subsMap, ok := d.changeNotify[peerID]
	subs := make([]*StatusChangeSubscription, 0, len(subsMap))
	if ok {
		for _, sub := range subsMap {
			subs = append(subs, sub)
		}
	}
	d.mux.Unlock()

	for _, sub := range subs {
		select {
		case sub.eventsChan <- routerPeers:
		case <-sub.ctx.Done():
		}
	}
}

func (d *Status) numOfPeers() int {
	return len(d.peers) + len(d.offlinePeers)
}

// PublishEvent adds an event to the queue and distributes it to all subscribers
func (d *Status) PublishEvent(
	severity proto.SystemEvent_Severity,
	category proto.SystemEvent_Category,
	msg string,
	userMsg string,
	metadata map[string]string,
) {
	event := &proto.SystemEvent{
		Id:          uuid.New().String(),
		Severity:    severity,
		Category:    category,
		Message:     msg,
		UserMessage: userMsg,
		Metadata:    metadata,
		Timestamp:   timestamppb.Now(),
	}

	d.eventMux.Lock()
	defer d.eventMux.Unlock()

	d.eventQueue.Add(event)

	for _, stream := range d.eventStreams {
		select {
		case stream <- event:
		default:
			log.Debugf("event stream buffer full, skipping event: %v", event)
		}
	}

	log.Debugf("event published: %v", event)
}

// SubscribeToEvents returns a new event subscription
func (d *Status) SubscribeToEvents() *EventSubscription {
	d.eventMux.Lock()
	defer d.eventMux.Unlock()

	id := uuid.New().String()
	stream := make(chan *proto.SystemEvent, 10)
	d.eventStreams[id] = stream

	return &EventSubscription{
		id:     id,
		events: stream,
	}
}

// UnsubscribeFromEvents removes an event subscription
func (d *Status) UnsubscribeFromEvents(sub *EventSubscription) {
	if sub == nil {
		return
	}

	d.eventMux.Lock()
	defer d.eventMux.Unlock()

	if stream, exists := d.eventStreams[sub.id]; exists {
		close(stream)
		delete(d.eventStreams, sub.id)
	}
}

// GetEventHistory returns all events in the queue
func (d *Status) GetEventHistory() []*proto.SystemEvent {
	return d.eventQueue.GetAll()
}

func (d *Status) SetWgIface(wgInterface WGIfaceStatus) {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.wgIface = wgInterface
}

func (d *Status) PeersStatus() (*configurer.Stats, error) {
	d.mux.Lock()
	defer d.mux.Unlock()
	if d.wgIface == nil {
		return nil, fmt.Errorf("wgInterface is nil, cannot retrieve peers status")
	}

	return d.wgIface.FullStats()
}

// RefreshWireGuardStats fetches fresh WireGuard statistics from the interface
// and updates the cached peer states. This ensures accurate handshake times and
// transfer statistics in status reports without running full health probes.
func (d *Status) RefreshWireGuardStats() error {
	d.mux.Lock()
	defer d.mux.Unlock()

	if d.wgIface == nil {
		return nil // silently skip if interface not set
	}

	stats, err := d.wgIface.FullStats()
	if err != nil {
		return fmt.Errorf("get wireguard stats: %w", err)
	}

	// Update each peer's WireGuard statistics
	for _, peerStats := range stats.Peers {
		peerState, ok := d.peers[peerStats.PublicKey]
		if !ok {
			continue
		}

		peerState.LastWireguardHandshake = peerStats.LastHandshake
		peerState.BytesRx = peerStats.RxBytes
		peerState.BytesTx = peerStats.TxBytes
		d.peers[peerStats.PublicKey] = peerState
	}

	return nil
}

type EventQueue struct {
	maxSize int
	events  []*proto.SystemEvent
	mutex   sync.RWMutex
}

func NewEventQueue(size int) *EventQueue {
	return &EventQueue{
		maxSize: size,
		events:  make([]*proto.SystemEvent, 0, size),
	}
}

func (q *EventQueue) Add(event *proto.SystemEvent) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	q.events = append(q.events, event)

	if len(q.events) > q.maxSize {
		q.events = q.events[len(q.events)-q.maxSize:]
	}
}

func (q *EventQueue) GetAll() []*proto.SystemEvent {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	return slices.Clone(q.events)
}

type EventSubscription struct {
	id     string
	events chan *proto.SystemEvent
}

func (s *EventSubscription) Events() <-chan *proto.SystemEvent {
	return s.events
}

// ToProto converts FullStatus to proto.FullStatus.
func (fs FullStatus) ToProto() *proto.FullStatus {
	pbFullStatus := proto.FullStatus{
		ManagementState: &proto.ManagementState{},
		SignalState:     &proto.SignalState{},
		LocalPeerState:  &proto.LocalPeerState{},
		Peers:           []*proto.PeerState{},
	}

	pbFullStatus.ManagementState.URL = fs.ManagementState.URL
	pbFullStatus.ManagementState.Connected = fs.ManagementState.Connected
	if err := fs.ManagementState.Error; err != nil {
		pbFullStatus.ManagementState.Error = err.Error()
	}

	pbFullStatus.SignalState.URL = fs.SignalState.URL
	pbFullStatus.SignalState.Connected = fs.SignalState.Connected
	if err := fs.SignalState.Error; err != nil {
		pbFullStatus.SignalState.Error = err.Error()
	}

	pbFullStatus.LocalPeerState.IP = fs.LocalPeerState.IP
	pbFullStatus.LocalPeerState.PubKey = fs.LocalPeerState.PubKey
	pbFullStatus.LocalPeerState.KernelInterface = fs.LocalPeerState.KernelInterface
	pbFullStatus.LocalPeerState.Fqdn = fs.LocalPeerState.FQDN
	pbFullStatus.LocalPeerState.RosenpassPermissive = fs.RosenpassState.Permissive
	pbFullStatus.LocalPeerState.RosenpassEnabled = fs.RosenpassState.Enabled
	pbFullStatus.NumberOfForwardingRules = int32(fs.NumOfForwardingRules)
	pbFullStatus.LazyConnectionEnabled = fs.LazyConnectionEnabled

	// Phase 3.7i (#5989): aggregate counters.
	pbFullStatus.ConfiguredPeersTotal = fs.ConfiguredPeersTotal
	pbFullStatus.ServerOnlinePeers = fs.ServerOnlinePeers
	pbFullStatus.P2PConnectedPeers = fs.P2PConnectedPeers
	pbFullStatus.RelayedConnectedPeers = fs.RelayedConnectedPeers
	pbFullStatus.IdleOnlinePeers = fs.IdleOnlinePeers
	pbFullStatus.ServerOfflinePeers = fs.ServerOfflinePeers

	pbFullStatus.LocalPeerState.Networks = maps.Keys(fs.LocalPeerState.Routes)

	for _, peerState := range fs.Peers {
		networks := maps.Keys(peerState.GetRoutes())

		pbPeerState := &proto.PeerState{
			IP:                         peerState.IP,
			PubKey:                     peerState.PubKey,
			ConnStatus:                 peerState.ConnStatus.String(),
			ConnStatusUpdate:           timestamppb.New(peerState.ConnStatusUpdate),
			Relayed:                    peerState.Relayed,
			LocalIceCandidateType:      peerState.LocalIceCandidateType,
			RemoteIceCandidateType:     peerState.RemoteIceCandidateType,
			LocalIceCandidateEndpoint:  peerState.LocalIceCandidateEndpoint,
			RemoteIceCandidateEndpoint: peerState.RemoteIceCandidateEndpoint,
			RelayAddress:               peerState.RelayServerAddress,
			Fqdn:                       peerState.FQDN,
			LastWireguardHandshake:     timestamppb.New(peerState.LastWireguardHandshake),
			BytesRx:                    peerState.BytesRx,
			BytesTx:                    peerState.BytesTx,
			RosenpassEnabled:           peerState.RosenpassEnabled,
			Networks:                   networks,
			Latency:                    durationpb.New(peerState.Latency),
			SshHostKey:                 peerState.SSHHostKey,
			IceBackoffFailures:         int32(peerState.IceBackoffFailures),
			IceBackoffNextRetry:        timestamppb.New(peerState.IceBackoffNextRetry),
			IceBackoffSuspended:        peerState.IceBackoffSuspended,
			// Phase 3.7i (#5989): per-peer remote meta fields.
			ServerOnline:               peerState.ServerOnline,
			Groups:                     peerState.RemoteGroups,
			EffectiveConnectionMode:    peerState.RemoteEffectiveConnectionMode,
			ConfiguredConnectionMode:   peerState.RemoteConfiguredConnectionMode,
			EffectiveRelayTimeoutSecs:  peerState.RemoteEffectiveRelayTimeoutSecs,
			EffectiveP2PTimeoutSecs:    peerState.RemoteEffectiveP2PTimeoutSecs,
			EffectiveP2PRetryMaxSecs:   peerState.RemoteEffectiveP2PRetryMaxSecs,
			ConfiguredRelayTimeoutSecs: peerState.RemoteConfiguredRelayTimeoutSecs,
			ConfiguredP2PTimeoutSecs:   peerState.RemoteConfiguredP2PTimeoutSecs,
			ConfiguredP2PRetryMaxSecs:  peerState.RemoteConfiguredP2PRetryMaxSecs,
		}
		if !peerState.RemoteLastSeenAtServer.IsZero() {
			pbPeerState.LastSeenAtServer = timestamppb.New(peerState.RemoteLastSeenAtServer)
		}
		pbFullStatus.Peers = append(pbFullStatus.Peers, pbPeerState)
	}

	for _, relayState := range fs.Relays {
		pbRelayState := &proto.RelayState{
			URI:       relayState.URI,
			Available: relayState.Err == nil,
		}
		if err := relayState.Err; err != nil {
			pbRelayState.Error = err.Error()
		}
		pbFullStatus.Relays = append(pbFullStatus.Relays, pbRelayState)
	}

	for _, dnsState := range fs.NSGroupStates {
		var err string
		if dnsState.Error != nil {
			err = dnsState.Error.Error()
		}

		var servers []string
		for _, server := range dnsState.Servers {
			servers = append(servers, server.String())
		}

		pbDnsState := &proto.NSGroupState{
			Servers: servers,
			Domains: dnsState.Domains,
			Enabled: dnsState.Enabled,
			Error:   err,
		}
		pbFullStatus.DnsServers = append(pbFullStatus.DnsServers, pbDnsState)
	}

	pbFullStatus.Events = fs.Events

	return &pbFullStatus
}
