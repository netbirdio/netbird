package peer

import (
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/relay"
	"github.com/netbirdio/netbird/iface"
)

// State contains the latest state of a peer
type State struct {
	Mux                        *sync.RWMutex
	IP                         string
	PubKey                     string
	FQDN                       string
	ConnStatus                 ConnStatus
	ConnStatusUpdate           time.Time
	Relayed                    bool
	Direct                     bool
	LocalIceCandidateType      string
	RemoteIceCandidateType     string
	LocalIceCandidateEndpoint  string
	RemoteIceCandidateEndpoint string
	LastWireguardHandshake     time.Time
	BytesTx                    int64
	BytesRx                    int64
	Latency                    time.Duration
	RosenpassEnabled           bool
	routes                     map[string]struct{}
}

// AddRoute add a single route to routes map
func (s *State) AddRoute(network string) {
	s.Mux.Lock()
	if s.routes == nil {
		s.routes = make(map[string]struct{})
	}
	s.routes[network] = struct{}{}
	s.Mux.Unlock()
}

// SetRoutes set state routes
func (s *State) SetRoutes(routes map[string]struct{}) {
	s.Mux.Lock()
	s.routes = routes
	s.Mux.Unlock()
}

// DeleteRoute removes a route from the network amp
func (s *State) DeleteRoute(network string) {
	s.Mux.Lock()
	delete(s.routes, network)
	s.Mux.Unlock()
}

// GetRoutes return routes map
func (s *State) GetRoutes() map[string]struct{} {
	s.Mux.RLock()
	defer s.Mux.RUnlock()
	return s.routes
}

// LocalPeerState contains the latest state of the local peer
type LocalPeerState struct {
	IP              string
	IP6             string
	PubKey          string
	KernelInterface bool
	FQDN            string
	Routes          map[string]struct{}
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
	Servers []string
	Domains []string
	Enabled bool
	Error   error
}

// FullStatus contains the full state held by the Status instance
type FullStatus struct {
	Peers           []State
	ManagementState ManagementState
	SignalState     SignalState
	LocalPeerState  LocalPeerState
	RosenpassState  RosenpassState
	Relays          []relay.ProbeResult
	NSGroupStates   []NSGroupState
}

// Status holds a state of peers, signal, management connections and relays
type Status struct {
	mux                 sync.Mutex
	peers               map[string]State
	changeNotify        map[string]chan struct{}
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
	nsGroupStates       []NSGroupState

	// To reduce the number of notification invocation this bool will be true when need to call the notification
	// Some Peer actions mostly used by in a batch when the network map has been synchronized. In these type of events
	// set to true this variable and at the end of the processing we will reset it by the FinishPeerListModifications()
	peerListChangedForNotification bool
}

// NewRecorder returns a new Status instance
func NewRecorder(mgmAddress string) *Status {
	return &Status{
		peers:        make(map[string]State),
		changeNotify: make(map[string]chan struct{}),
		offlinePeers: make([]State, 0),
		notifier:     newNotifier(),
		mgmAddress:   mgmAddress,
	}
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
func (d *Status) AddPeer(peerPubKey string, fqdn string) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	_, ok := d.peers[peerPubKey]
	if ok {
		return errors.New("peer already exist")
	}
	d.peers[peerPubKey] = State{
		PubKey:     peerPubKey,
		ConnStatus: StatusDisconnected,
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
		return State{}, errors.New("peer not found")
	}
	return state, nil
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
	d.mux.Lock()
	defer d.mux.Unlock()

	peerState, ok := d.peers[receivedState.PubKey]
	if !ok {
		return errors.New("peer doesn't exist")
	}

	if receivedState.IP != "" {
		peerState.IP = receivedState.IP
	}

	if receivedState.GetRoutes() != nil {
		peerState.SetRoutes(receivedState.GetRoutes())
	}

	skipNotification := shouldSkipNotify(receivedState, peerState)

	if receivedState.ConnStatus != peerState.ConnStatus {
		peerState.ConnStatus = receivedState.ConnStatus
		peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
		peerState.Direct = receivedState.Direct
		peerState.Relayed = receivedState.Relayed
		peerState.LocalIceCandidateType = receivedState.LocalIceCandidateType
		peerState.RemoteIceCandidateType = receivedState.RemoteIceCandidateType
		peerState.LocalIceCandidateEndpoint = receivedState.LocalIceCandidateEndpoint
		peerState.RemoteIceCandidateEndpoint = receivedState.RemoteIceCandidateEndpoint
		peerState.RosenpassEnabled = receivedState.RosenpassEnabled
	}

	d.peers[receivedState.PubKey] = peerState

	if skipNotification {
		return nil
	}

	ch, found := d.changeNotify[receivedState.PubKey]
	if found && ch != nil {
		close(ch)
		d.changeNotify[receivedState.PubKey] = nil
	}

	d.notifyPeerListChanged()
	return nil
}

// UpdateWireGuardPeerState updates the WireGuard bits of the peer state
func (d *Status) UpdateWireGuardPeerState(pubKey string, wgStats iface.WGStats) error {
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

func shouldSkipNotify(received, curr State) bool {
	switch {
	case received.ConnStatus == StatusConnecting:
		return true
	case received.ConnStatus == StatusDisconnected && curr.ConnStatus == StatusConnecting:
		return true
	case received.ConnStatus == StatusDisconnected && curr.ConnStatus == StatusDisconnected:
		return curr.IP != ""
	default:
		return false
	}
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

// FinishPeerListModifications this event invoke the notification
func (d *Status) FinishPeerListModifications() {
	d.mux.Lock()

	if !d.peerListChangedForNotification {
		d.mux.Unlock()
		return
	}
	d.peerListChangedForNotification = false
	d.mux.Unlock()

	d.notifyPeerListChanged()
}

// GetPeerStateChangeNotifier returns a change notifier channel for a peer
func (d *Status) GetPeerStateChangeNotifier(peer string) <-chan struct{} {
	d.mux.Lock()
	defer d.mux.Unlock()
	ch, found := d.changeNotify[peer]
	if !found || ch == nil {
		ch = make(chan struct{})
		d.changeNotify[peer] = ch
	}
	return ch
}

// GetLocalPeerState returns the local peer state
func (d *Status) GetLocalPeerState() LocalPeerState {
	d.mux.Lock()
	defer d.mux.Unlock()
	return d.localPeer
}

// UpdateLocalPeerState updates local peer status
func (d *Status) UpdateLocalPeerState(localPeerState LocalPeerState) {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.localPeer = localPeerState
	d.notifyAddressChanged()
}

// CleanLocalPeerState cleans local peer status
func (d *Status) CleanLocalPeerState() {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.localPeer = LocalPeerState{}
	d.notifyAddressChanged()
}

// MarkManagementDisconnected sets ManagementState to disconnected
func (d *Status) MarkManagementDisconnected(err error) {
	d.mux.Lock()
	defer d.mux.Unlock()
	defer d.onConnectionChanged()

	d.managementState = false
	d.managementError = err
}

// MarkManagementConnected sets ManagementState to connected
func (d *Status) MarkManagementConnected() {
	d.mux.Lock()
	defer d.mux.Unlock()
	defer d.onConnectionChanged()

	d.managementState = true
	d.managementError = nil
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

// MarkSignalDisconnected sets SignalState to disconnected
func (d *Status) MarkSignalDisconnected(err error) {
	d.mux.Lock()
	defer d.mux.Unlock()
	defer d.onConnectionChanged()

	d.signalState = false
	d.signalError = err
}

// MarkSignalConnected sets SignalState to connected
func (d *Status) MarkSignalConnected() {
	d.mux.Lock()
	defer d.mux.Unlock()
	defer d.onConnectionChanged()

	d.signalState = true
	d.signalError = nil
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

func (d *Status) GetRosenpassState() RosenpassState {
	return RosenpassState{
		d.rosenpassEnabled,
		d.rosenpassPermissive,
	}
}

func (d *Status) GetManagementState() ManagementState {
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
	return SignalState{
		d.signalAddress,
		d.signalState,
		d.signalError,
	}
}

func (d *Status) GetRelayStates() []relay.ProbeResult {
	return d.relayStates
}

func (d *Status) GetDNSStates() []NSGroupState {
	return d.nsGroupStates
}

// GetFullStatus gets full status
func (d *Status) GetFullStatus() FullStatus {
	d.mux.Lock()
	defer d.mux.Unlock()

	fullStatus := FullStatus{
		ManagementState: d.GetManagementState(),
		SignalState:     d.GetSignalState(),
		LocalPeerState:  d.localPeer,
		Relays:          d.GetRelayStates(),
		RosenpassState:  d.GetRosenpassState(),
		NSGroupStates:   d.GetDNSStates(),
	}

	for _, status := range d.peers {
		fullStatus.Peers = append(fullStatus.Peers, status)
	}

	fullStatus.Peers = append(fullStatus.Peers, d.offlinePeers...)

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

func (d *Status) onConnectionChanged() {
	d.notifier.updateServerStates(d.managementState, d.signalState)
}

func (d *Status) notifyPeerListChanged() {
	d.notifier.peerListChanged(d.numOfPeers())
}

func (d *Status) notifyAddressChanged() {
	d.notifier.localAddressChanged(d.localPeer.FQDN, d.localPeer.IP)
}

func (d *Status) numOfPeers() int {
	return len(d.peers) + len(d.offlinePeers)
}
