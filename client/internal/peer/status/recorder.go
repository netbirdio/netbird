package status

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
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

var errPeerNotExists = errors.New("peer doesn't exist")

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

// LocalPeerState contains the latest state of the local peer
type LocalPeerState struct {
	IP              string
	IPv6            string
	PubKey          string
	KernelInterface bool
	FQDN            string
	WgPort          int
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

// Recorder holds a state of peers, signal, management connections and relays.
// mux is an RWMutex so hot read paths (notably PeerStateByIP, called for
// every private-service request) don't contend against each other.
// Pure read methods take RLock; anything that mutates state takes Lock.
type Recorder struct {
	mux                 sync.RWMutex
	muxRelays           sync.RWMutex
	peers               map[string]State
	ipToKey             map[string]string
	changeNotify        map[string]map[string]*StatusChangeSubscription // map[peerID]map[subscriptionID]*StatusChangeSubscription
	signalState         bool
	signalError         error
	managementState     bool
	managementError     error
	relayStates         []relay.ProbeResult
	localPeer           LocalPeerState
	offlinePeers        []State
	mgmAddress          string
	signalAddress       string
	notifier            *notifier
	rosenpassEnabled    bool
	rosenpassPermissive bool
	// sessionExpiresAt is the absolute UTC instant at which the peer's SSO
	// session expires. Zero when the peer is not SSO-tracked or login
	// expiration is disabled. Populated from management LoginResponse /
	// SyncResponse and exposed via the daemon's Status / SubscribeStatus RPC
	// so the UI can show remaining time without itself talking to mgm.
	sessionExpiresAt time.Time

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

	// stateChangeStreams fan-out connection-state changes (connected /
	// disconnected / connecting / address change / peers list change) to
	// every active SubscribeStatus gRPC stream. Each subscriber gets a
	// buffered chan; the notifier non-blockingly pings them so a slow
	// consumer can never stall the daemon.
	stateChangeMux     sync.Mutex
	stateChangeStreams map[string]chan struct{}

	// networksRevision bumps whenever the routed-networks set or their
	// selected state changes (driven by the route manager). Surfaced in the
	// status snapshot so the UI can fingerprint on it and re-fetch
	// ListNetworks only on a real change. Atomic so the snapshot builder can
	// read it without taking mux.
	networksRevision atomic.Uint64

	ingressGwMgr *ingressgw.Manager

	routeIDLookup routeIDLookup
	wgIface       WGIfaceStatus
}

// NewRecorder returns a new Recorder instance
func NewRecorder(mgmAddress string) *Recorder {
	return &Recorder{
		peers:                 make(map[string]State),
		ipToKey:               make(map[string]string),
		changeNotify:          make(map[string]map[string]*StatusChangeSubscription),
		eventStreams:          make(map[string]chan *proto.SystemEvent),
		eventQueue:            NewEventQueue(eventQueueSize),
		stateChangeStreams:    make(map[string]chan struct{}),
		offlinePeers:          make([]State, 0),
		notifier:              newNotifier(),
		mgmAddress:            mgmAddress,
		resolvedDomainsStates: map[domain.Domain]ResolvedDomainInfo{},
	}
}

func (d *Recorder) SetRelayMgr(manager *relayClient.Manager) {
	d.muxRelays.Lock()
	defer d.muxRelays.Unlock()
	d.relayMgr = manager
}

func (d *Recorder) SetIngressGwMgr(ingressGwMgr *ingressgw.Manager) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.ingressGwMgr = ingressGwMgr
}

// ReplaceOfflinePeers replaces
func (d *Recorder) ReplaceOfflinePeers(replacement []State) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.offlinePeers = make([]State, len(replacement))
	copy(d.offlinePeers, replacement)

	// todo we should set to true in case if the list changed only
	d.peerListChangedForNotification = true
}

// AddPeer adds peer to Daemon status map
func (d *Recorder) AddPeer(peerPubKey string, fqdn string, ip string, ipv6 string) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	_, ok := d.peers[peerPubKey]
	if ok {
		return errors.New("peer already exist")
	}
	d.peers[peerPubKey] = State{
		PubKey:     peerPubKey,
		IP:         ip,
		IPv6:       ipv6,
		ConnStatus: StatusIdle,
		FQDN:       fqdn,
		Mux:        new(sync.RWMutex),
	}
	d.peerListChangedForNotification = true
	if ipv6 != "" {
		d.ipToKey[ipv6] = peerPubKey
	}
	if ip != "" {
		d.ipToKey[ip] = peerPubKey
	}
	return nil
}

// GetPeer adds peer to Daemon status map
func (d *Recorder) GetPeer(peerPubKey string) (State, error) {
	d.mux.RLock()
	defer d.mux.RUnlock()

	state, ok := d.peers[peerPubKey]
	if !ok {
		return State{}, configurer.ErrPeerNotFound
	}
	return state, nil
}

func (d *Recorder) PeerByIP(ip string) (string, bool) {
	d.mux.RLock()
	defer d.mux.RUnlock()

	for _, state := range d.peers {
		if state.IP == ip {
			return state.FQDN, true
		}
	}
	return "", false
}

// PeerStateByIP returns the full peer State for the given tunnel IP.
// Matches against either the IPv4 (State.IP) or IPv6 (State.IPv6) tunnel
// address so dual-stack peers are reachable on either family. Only
// active peers are matched; peers moved into the offline slice by
// ReplaceOfflinePeers are intentionally treated as unknown.
func (d *Recorder) PeerStateByIP(ip string) (State, bool) {
	if ip == "" {
		return State{}, false
	}
	d.mux.RLock()
	defer d.mux.RUnlock()
	key, ok := d.ipToKey[ip]
	if !ok {
		return State{}, false
	}
	state, ok := d.peers[key]
	if ok {
		return state, true
	}
	return State{}, false
}

// RemovePeer removes peer from Daemon status map
func (d *Recorder) RemovePeer(peerPubKey string) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	p, ok := d.peers[peerPubKey]
	if !ok {
		return errors.New("no peer with to remove")
	}

	delete(d.peers, peerPubKey)
	if mappedKey, exists := d.ipToKey[p.IP]; exists && mappedKey == peerPubKey {
		delete(d.ipToKey, p.IP)
	}
	if mappedKey, exists := d.ipToKey[p.IPv6]; exists && mappedKey == peerPubKey {
		delete(d.ipToKey, p.IPv6)
	}
	d.peerListChangedForNotification = true
	return nil
}

// UpdatePeerState updates peer status
func (d *Recorder) UpdatePeerState(receivedState State) error {
	return d.updatePeer(receivedState.PubKey,
		func(_, updated State) bool { return updated.ConnStatus == StatusIdle },
		func(peerState *State) {
			if receivedState.ConnStatus == peerState.ConnStatus {
				return
			}
			peerState.ConnStatus = receivedState.ConnStatus
			peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
			peerState.Relayed = receivedState.Relayed
			peerState.LocalIceCandidateType = receivedState.LocalIceCandidateType
			peerState.RemoteIceCandidateType = receivedState.RemoteIceCandidateType
			peerState.LocalIceCandidateEndpoint = receivedState.LocalIceCandidateEndpoint
			peerState.RemoteIceCandidateEndpoint = receivedState.RemoteIceCandidateEndpoint
			peerState.RelayServerAddress = receivedState.RelayServerAddress
			peerState.RosenpassEnabled = receivedState.RosenpassEnabled
		})
}

func (d *Recorder) AddPeerStateRoute(peer string, route string, resourceId route.ResID) error {
	d.mux.Lock()

	peerState, ok := d.peers[peer]
	if !ok {
		d.mux.Unlock()
		return errPeerNotExists
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
	d.notifyStateChange()
	return nil
}

func (d *Recorder) RemovePeerStateRoute(peer string, route string) error {
	d.mux.Lock()

	peerState, ok := d.peers[peer]
	if !ok {
		d.mux.Unlock()
		return errPeerNotExists
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
	d.notifyStateChange()
	return nil
}

// CheckRoutes checks if the source and destination addresses are within the same route
// and returns the resource ID of the route that contains the addresses
func (d *Recorder) CheckRoutes(ip netip.Addr) ([]byte, bool) {
	if d == nil {
		return nil, false
	}
	resId, isExitNode := d.routeIDLookup.Lookup(ip)
	return []byte(resId), isExitNode
}

func (d *Recorder) UpdatePeerICEState(receivedState State) error {
	return d.updatePeer(receivedState.PubKey, hasStatusOrRelayedChange, func(peerState *State) {
		peerState.ConnStatus = receivedState.ConnStatus
		peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
		peerState.Relayed = receivedState.Relayed
		peerState.LocalIceCandidateType = receivedState.LocalIceCandidateType
		peerState.RemoteIceCandidateType = receivedState.RemoteIceCandidateType
		peerState.LocalIceCandidateEndpoint = receivedState.LocalIceCandidateEndpoint
		peerState.RemoteIceCandidateEndpoint = receivedState.RemoteIceCandidateEndpoint
		peerState.RosenpassEnabled = receivedState.RosenpassEnabled
	})
}

func (d *Recorder) UpdatePeerRelayedState(receivedState State) error {
	return d.updatePeer(receivedState.PubKey, hasStatusOrRelayedChange, func(peerState *State) {
		peerState.ConnStatus = receivedState.ConnStatus
		peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
		peerState.Relayed = receivedState.Relayed
		peerState.RelayServerAddress = receivedState.RelayServerAddress
		peerState.RosenpassEnabled = receivedState.RosenpassEnabled
	})
}

func (d *Recorder) UpdatePeerRelayedStateToDisconnected(receivedState State) error {
	return d.updatePeer(receivedState.PubKey, hasStatusOrRelayedChange, func(peerState *State) {
		peerState.ConnStatus = receivedState.ConnStatus
		peerState.Relayed = receivedState.Relayed
		peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
		peerState.RelayServerAddress = ""
	})
}

func (d *Recorder) UpdatePeerICEStateToDisconnected(receivedState State) error {
	return d.updatePeer(receivedState.PubKey, hasStatusOrRelayedChange, func(peerState *State) {
		peerState.ConnStatus = receivedState.ConnStatus
		peerState.Relayed = receivedState.Relayed
		peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
		peerState.LocalIceCandidateType = receivedState.LocalIceCandidateType
		peerState.RemoteIceCandidateType = receivedState.RemoteIceCandidateType
		peerState.LocalIceCandidateEndpoint = receivedState.LocalIceCandidateEndpoint
		peerState.RemoteIceCandidateEndpoint = receivedState.RemoteIceCandidateEndpoint
	})
}

// UpdateWireGuardPeerState updates the WireGuard bits of the peer state
func (d *Recorder) UpdateWireGuardPeerState(pubKey string, wgStats configurer.WGStats) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	peerState, ok := d.peers[pubKey]
	if !ok {
		return errPeerNotExists
	}

	peerState.LastWireguardHandshake = wgStats.LastHandshake
	peerState.BytesRx = wgStats.RxBytes
	peerState.BytesTx = wgStats.TxBytes

	d.peers[pubKey] = peerState

	return nil
}

// updatePeer applies mutate to the stored peer state and runs the list, router
// and state-change notifications outside the lock
func (d *Recorder) updatePeer(pubKey string, notifyRouter func(old, updated State) bool, mutate func(*State)) error {
	d.mux.Lock()

	peerState, ok := d.peers[pubKey]
	if !ok {
		d.mux.Unlock()
		return errPeerNotExists
	}

	oldState := peerState
	mutate(&peerState)
	d.peers[pubKey] = peerState

	notifyList := oldState.ConnStatus != peerState.ConnStatus
	router := notifyRouter(oldState, peerState)
	routerSnapshot := d.snapshotRouterPeersLocked(pubKey, router)
	numPeers := d.numOfPeers()

	d.mux.Unlock()

	if notifyList {
		d.notifier.peerListChanged(numPeers)
	}
	if router {
		d.dispatchRouterPeers(pubKey, routerSnapshot)
	}
	d.notifyStateChange()
	return nil
}

// UpdatePeerFQDN update peer's state fqdn only
func (d *Recorder) UpdatePeerFQDN(peerPubKey, fqdn string) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	peerState, ok := d.peers[peerPubKey]
	if !ok {
		return errPeerNotExists
	}

	peerState.FQDN = fqdn
	d.peers[peerPubKey] = peerState

	return nil
}

// UpdatePeerSSHHostKey updates peer's SSH host key
func (d *Recorder) UpdatePeerSSHHostKey(peerPubKey string, sshHostKey []byte) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	peerState, ok := d.peers[peerPubKey]
	if !ok {
		return errPeerNotExists
	}

	peerState.SSHHostKey = sshHostKey
	d.peers[peerPubKey] = peerState

	return nil
}

// FinishPeerListModifications this event invoke the notification
func (d *Recorder) FinishPeerListModifications() {
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
	d.notifyStateChange()
}

func (d *Recorder) SubscribeToPeerStateChanges(ctx context.Context, peerID string) *StatusChangeSubscription {
	d.mux.Lock()
	defer d.mux.Unlock()

	sub := newStatusChangeSubscription(ctx, peerID)
	if _, ok := d.changeNotify[peerID]; !ok {
		d.changeNotify[peerID] = make(map[string]*StatusChangeSubscription)
	}
	d.changeNotify[peerID][sub.id] = sub

	return sub
}

func (d *Recorder) UnsubscribePeerStateChanges(subscription *StatusChangeSubscription) {
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
func (d *Recorder) GetLocalPeerState() LocalPeerState {
	d.mux.RLock()
	defer d.mux.RUnlock()
	return d.localPeer.Clone()
}

// UpdateLocalPeerState updates local peer status
func (d *Recorder) UpdateLocalPeerState(localPeerState LocalPeerState) {
	d.mux.Lock()
	d.localPeer = localPeerState
	fqdn := d.localPeer.FQDN
	ip := d.localPeer.IP
	if d.localPeer.IPv6 != "" {
		ip = ip + "\n" + d.localPeer.IPv6
	}
	d.mux.Unlock()

	d.notifier.localAddressChanged(fqdn, ip)
	d.notifyStateChange()
}

// SetSessionExpiresAt records the absolute UTC instant at which the peer's
// SSO session is set to expire. Pass the zero value to clear (e.g. when the
// management server stops publishing a deadline because login expiration was
// disabled or the peer is not SSO-tracked). Same-value updates are no-ops;
// real changes fan out via notifyStateChange so SubscribeStatus consumers
// pick up the new deadline on their next read.
func (d *Recorder) SetSessionExpiresAt(deadline time.Time) {
	d.mux.Lock()
	if d.sessionExpiresAt.Equal(deadline) {
		d.mux.Unlock()
		return
	}
	d.sessionExpiresAt = deadline
	d.mux.Unlock()
	d.notifyStateChange()
}

// GetSessionExpiresAt returns the most recently recorded SSO session deadline,
// or the zero value when no deadline is tracked. A deadline that has already
// slipped into the past reports as "none": once the session has expired it is
// no longer a meaningful countdown, and the sessionwatch.Watcher does not
// arm a timer at the deadline itself to clear it (only the two pre-expiry
// warnings). Without this guard the UI would keep painting a stale
// "expires in …" against a moment that has passed until the next login,
// extend, or teardown rewrote the value.
func (d *Recorder) GetSessionExpiresAt() time.Time {
	d.mux.Lock()
	defer d.mux.Unlock()
	if !d.sessionExpiresAt.IsZero() && d.sessionExpiresAt.Before(time.Now()) {
		return time.Time{}
	}
	return d.sessionExpiresAt
}

// AddLocalPeerStateRoute adds a route to the local peer state
func (d *Recorder) AddLocalPeerStateRoute(route string, resourceId route.ResID) {
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
func (d *Recorder) RemoveLocalPeerStateRoute(route string) {
	d.mux.Lock()
	defer d.mux.Unlock()

	pref, err := netip.ParsePrefix(route)
	if err == nil {
		d.routeIDLookup.RemoveLocalRouteID(pref)
	}

	delete(d.localPeer.Routes, route)
}

// AddResolvedIPLookupEntry adds a resolved IP lookup entry
func (d *Recorder) AddResolvedIPLookupEntry(prefix netip.Prefix, resourceId route.ResID) {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.routeIDLookup.AddResolvedIP(resourceId, prefix)
}

// RemoveResolvedIPLookupEntry removes a resolved IP lookup entry
func (d *Recorder) RemoveResolvedIPLookupEntry(route string) {
	d.mux.Lock()
	defer d.mux.Unlock()

	pref, err := netip.ParsePrefix(route)
	if err == nil {
		d.routeIDLookup.RemoveResolvedIP(pref)
	}
}

// CleanLocalPeerStateRoutes cleans all routes from the local peer state
func (d *Recorder) CleanLocalPeerStateRoutes() {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.localPeer.Routes = map[string]struct{}{}
}

// CleanLocalPeerState cleans local peer status
func (d *Recorder) CleanLocalPeerState() {
	d.mux.Lock()
	d.localPeer = LocalPeerState{}
	fqdn := d.localPeer.FQDN
	ip := d.localPeer.IP
	d.mux.Unlock()

	d.notifier.localAddressChanged(fqdn, ip)
	d.notifyStateChange()
}

// MarkManagementDisconnected sets ManagementState to disconnected
func (d *Recorder) MarkManagementDisconnected(err error) {
	d.mux.Lock()
	// Health checks re-mark the same state on every probe; skip the fan-out
	// when nothing actually changed so we don't flood SubscribeStatus
	// consumers with identical snapshots.
	if !d.managementState && errors.Is(d.managementError, err) {
		d.mux.Unlock()
		return
	}
	d.managementState = false
	d.managementError = err
	mgm := d.managementState
	sig := d.signalState
	d.mux.Unlock()

	d.notifier.updateServerStates(mgm, sig)
	d.notifyStateChange()
}

// MarkManagementConnected sets ManagementState to connected
func (d *Recorder) MarkManagementConnected() {
	d.mux.Lock()
	if d.managementState && d.managementError == nil {
		d.mux.Unlock()
		return
	}
	d.managementState = true
	d.managementError = nil
	mgm := d.managementState
	sig := d.signalState
	d.mux.Unlock()

	d.notifier.updateServerStates(mgm, sig)
	d.notifyStateChange()
}

// UpdateSignalAddress update the address of the signal server
func (d *Recorder) UpdateSignalAddress(signalURL string) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.signalAddress = signalURL
}

// UpdateManagementAddress update the address of the management server
func (d *Recorder) UpdateManagementAddress(mgmAddress string) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.mgmAddress = mgmAddress
}

// UpdateRosenpass update the Rosenpass configuration
func (d *Recorder) UpdateRosenpass(rosenpassEnabled, rosenpassPermissive bool) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.rosenpassPermissive = rosenpassPermissive
	d.rosenpassEnabled = rosenpassEnabled
}

func (d *Recorder) UpdateLazyConnection(enabled bool) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.lazyConnectionEnabled = enabled
}

// MarkSignalDisconnected sets SignalState to disconnected
func (d *Recorder) MarkSignalDisconnected(err error) {
	d.mux.Lock()
	if !d.signalState && errors.Is(d.signalError, err) {
		d.mux.Unlock()
		return
	}
	d.signalState = false
	d.signalError = err
	mgm := d.managementState
	sig := d.signalState
	d.mux.Unlock()

	d.notifier.updateServerStates(mgm, sig)
	d.notifyStateChange()
}

// MarkSignalConnected sets SignalState to connected
func (d *Recorder) MarkSignalConnected() {
	d.mux.Lock()
	if d.signalState && d.signalError == nil {
		d.mux.Unlock()
		return
	}
	d.signalState = true
	d.signalError = nil
	mgm := d.managementState
	sig := d.signalState
	d.mux.Unlock()

	d.notifier.updateServerStates(mgm, sig)
	d.notifyStateChange()
}

func (d *Recorder) UpdateRelayStates(relayResults []relay.ProbeResult) {
	d.muxRelays.Lock()
	defer d.muxRelays.Unlock()
	d.relayStates = relayResults
}

func (d *Recorder) UpdateDNSStates(dnsStates []NSGroupState) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.nsGroupStates = dnsStates
}

func (d *Recorder) UpdateResolvedDomainsStates(originalDomain domain.Domain, resolvedDomain domain.Domain, prefixes []netip.Prefix, resourceId route.ResID) {
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

func (d *Recorder) DeleteResolvedDomainsStates(domain domain.Domain) {
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

func (d *Recorder) GetRosenpassState() RosenpassState {
	d.mux.RLock()
	defer d.mux.RUnlock()
	return RosenpassState{
		d.rosenpassEnabled,
		d.rosenpassPermissive,
	}
}

func (d *Recorder) GetLazyConnection() bool {
	d.mux.RLock()
	defer d.mux.RUnlock()
	return d.lazyConnectionEnabled
}

func (d *Recorder) GetManagementState() ManagementState {
	d.mux.RLock()
	defer d.mux.RUnlock()
	return ManagementState{
		d.mgmAddress,
		d.managementState,
		d.managementError,
	}
}

func (d *Recorder) UpdateLatency(pubKey string, latency time.Duration) error {
	if latency <= 0 {
		return nil
	}

	d.mux.Lock()
	defer d.mux.Unlock()
	peerState, ok := d.peers[pubKey]
	if !ok {
		return errPeerNotExists
	}
	peerState.Latency = latency
	d.peers[pubKey] = peerState
	return nil
}

// IsLoginRequired determines if a peer's login has expired.
func (d *Recorder) IsLoginRequired() bool {
	d.mux.RLock()
	defer d.mux.RUnlock()

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

func (d *Recorder) GetSignalState() SignalState {
	d.mux.RLock()
	defer d.mux.RUnlock()
	return SignalState{
		d.signalAddress,
		d.signalState,
		d.signalError,
	}
}

// GetRelayStates returns the stun/turn/permanent relay states
func (d *Recorder) GetRelayStates() []relay.ProbeResult {
	d.muxRelays.RLock()
	if d.relayMgr == nil {
		defer d.muxRelays.RUnlock()
		return slices.Clone(d.relayStates)
	}

	relayMgr := d.relayMgr
	// extend the list of stun, turn servers with the relay server connections
	relayStates := slices.Clone(d.relayStates)
	d.muxRelays.RUnlock()

	states := relayMgr.RelayStates()
	if len(states) == 0 {
		// no relay connection tracked yet; surface configured servers as
		// unavailable with the real reconnect error when known
		err := relayClient.ErrRelayClientNotConnected
		if connErr := relayMgr.RelayConnectError(); connErr != nil {
			err = connErr
		}
		for _, r := range relayMgr.ServerURLs() {
			relayStates = append(relayStates, relay.ProbeResult{
				URI: r,
				Err: err,
			})
		}
		return relayStates
	}

	for _, rs := range states {
		relayStates = append(relayStates, relay.ProbeResult{
			URI:       rs.URL,
			Err:       rs.Err,
			Transport: rs.Transport,
		})
	}
	return relayStates
}

func (d *Recorder) ForwardingRules() []firewall.ForwardRule {
	d.mux.RLock()
	defer d.mux.RUnlock()
	if d.ingressGwMgr == nil {
		return nil
	}

	return d.ingressGwMgr.Rules()
}

func (d *Recorder) GetDNSStates() []NSGroupState {
	d.mux.RLock()
	defer d.mux.RUnlock()

	// shallow copy is good enough, as slices fields are currently not updated
	return slices.Clone(d.nsGroupStates)
}

func (d *Recorder) GetResolvedDomainsStates() map[domain.Domain]ResolvedDomainInfo {
	d.mux.RLock()
	defer d.mux.RUnlock()
	return maps.Clone(d.resolvedDomainsStates)
}

// GetFullStatus gets full status
func (d *Recorder) GetFullStatus() FullStatus {
	fullStatus := FullStatus{
		ManagementState:       d.GetManagementState(),
		SignalState:           d.GetSignalState(),
		Relays:                d.GetRelayStates(),
		RosenpassState:        d.GetRosenpassState(),
		NSGroupStates:         d.GetDNSStates(),
		NumOfForwardingRules:  len(d.ForwardingRules()),
		LazyConnectionEnabled: d.GetLazyConnection(),
	}

	d.mux.RLock()
	defer d.mux.RUnlock()

	fullStatus.LocalPeerState = d.localPeer

	for _, status := range d.peers {
		fullStatus.Peers = append(fullStatus.Peers, status)
	}

	fullStatus.Peers = append(fullStatus.Peers, d.offlinePeers...)
	fullStatus.Events = d.GetEventHistory()
	return fullStatus
}

// ClientStart will notify all listeners about the new service state
func (d *Recorder) ClientStart() {
	d.notifier.clientStart()
	d.notifyStateChange()
}

// ClientStop will notify all listeners about the new service state
func (d *Recorder) ClientStop() {
	d.notifier.clientStop()
	d.notifyStateChange()
}

// ClientTeardown will notify all listeners about the service is under teardown
func (d *Recorder) ClientTeardown() {
	d.notifier.clientTearDown()
	d.notifyStateChange()
}

// SetConnectionListener set a listener to the notifier
func (d *Recorder) SetConnectionListener(listener Listener) {
	d.notifier.setListener(listener)
}

// RemoveConnectionListener remove the listener from the notifier
func (d *Recorder) RemoveConnectionListener() {
	d.notifier.removeListener()
}

// snapshotRouterPeersLocked builds the RouterState map for a peer's subscribers.
// Caller MUST hold d.mux. Returns nil when there are no subscribers for peerID
// or when notify is false. The snapshot is consumed later by dispatchRouterPeers
// outside the lock so the channel send cannot stall any d.mux holder.
func (d *Recorder) snapshotRouterPeersLocked(peerID string, notify bool) map[string]RouterState {
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
func (d *Recorder) dispatchRouterPeers(peerID string, routerPeers map[string]RouterState) {
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

func (d *Recorder) numOfPeers() int {
	return len(d.peers) + len(d.offlinePeers)
}

// PublishEvent adds an event to the queue and distributes it to all subscribers
func (d *Recorder) PublishEvent(
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
func (d *Recorder) SubscribeToEvents() *EventSubscription {
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
func (d *Recorder) UnsubscribeFromEvents(sub *EventSubscription) {
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
func (d *Recorder) GetEventHistory() []*proto.SystemEvent {
	return d.eventQueue.GetAll()
}

// SubscribeToStateChanges hands back a channel that receives a tick on
// every connection-state change (connected / disconnected / connecting /
// address change / peers-list change). The channel is buffered to one
// pending tick so a coalesced burst still wakes the consumer exactly
// once. Pass the returned id to UnsubscribeFromStateChanges to detach.
func (d *Recorder) SubscribeToStateChanges() (string, <-chan struct{}) {
	d.stateChangeMux.Lock()
	defer d.stateChangeMux.Unlock()

	id := uuid.New().String()
	ch := make(chan struct{}, 1)
	d.stateChangeStreams[id] = ch
	return id, ch
}

// UnsubscribeFromStateChanges releases a SubscribeToStateChanges channel
// and closes it so any consumer goroutine selecting on the channel
// unblocks cleanly.
func (d *Recorder) UnsubscribeFromStateChanges(id string) {
	d.stateChangeMux.Lock()
	defer d.stateChangeMux.Unlock()

	if ch, ok := d.stateChangeStreams[id]; ok {
		close(ch)
		delete(d.stateChangeStreams, id)
	}
}

// notifyStateChange wakes every SubscribeToStateChanges subscriber. Drops
// the tick if a subscriber's buffer is full — by definition the consumer
// is already going to fetch the latest snapshot, so multiple pending ticks
// would be redundant.
func (d *Recorder) notifyStateChange() {
	d.stateChangeMux.Lock()
	defer d.stateChangeMux.Unlock()

	for _, ch := range d.stateChangeStreams {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// NotifyStateChange is the public wake-the-subscribers entry point used by
// callers that mutate state outside the peer recorder — most importantly
// the connect-state machine, which writes StatusNeedsLogin into the
// shared contextState (client/internal/state.go) without touching any
// recorder field. Without this push the SubscribeStatus stream stays on
// the previous snapshot until an unrelated peer/management/signal
// change happens to fire notifyStateChange, leaving the UI's status
// out of sync with the daemon.
func (d *Recorder) NotifyStateChange() {
	d.notifyStateChange()
}

// BumpNetworksRevision increments the routed-networks revision and wakes every
// SubscribeStatus subscriber. The route manager calls it when a network map
// changes the available routes or when a selection is applied — the peer
// status itself only records actively-routed (chosen) networks, so without
// this bump a candidate route appearing/disappearing would never reach the UI.
func (d *Recorder) BumpNetworksRevision() {
	d.networksRevision.Add(1)
	d.notifyStateChange()
}

// GetNetworksRevision returns the current routed-networks revision, surfaced in
// the status snapshot so the UI can detect route/selection changes (see
// BumpNetworksRevision).
func (d *Recorder) GetNetworksRevision() uint64 {
	return d.networksRevision.Load()
}

func (d *Recorder) SetWgIface(wgInterface WGIfaceStatus) {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.wgIface = wgInterface
}

func (d *Recorder) PeersStatus() (*configurer.Stats, error) {
	d.mux.RLock()
	defer d.mux.RUnlock()
	if d.wgIface == nil {
		return nil, fmt.Errorf("wgInterface is nil, cannot retrieve peers status")
	}

	return d.wgIface.FullStats()
}

// RefreshWireGuardStats fetches fresh WireGuard statistics from the interface
// and updates the cached peer states. This ensures accurate handshake times and
// transfer statistics in status reports without running full health probes.
func (d *Recorder) RefreshWireGuardStats() error {
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

func hasStatusOrRelayedChange(old, updated State) bool {
	return old.Relayed != updated.Relayed || old.ConnStatus != updated.ConnStatus
}
