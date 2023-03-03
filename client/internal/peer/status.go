package peer

import (
	"errors"
	"sync"
	"time"
)

// PeerState contains the latest state of a peer
type PeerState struct {
	IP                     string
	PubKey                 string
	FQDN                   string
	ConnStatus             ConnStatus
	ConnStatusUpdate       time.Time
	Relayed                bool
	Direct                 bool
	LocalIceCandidateType  string
	RemoteIceCandidateType string
}

// LocalPeerState contains the latest state of the local peer
type LocalPeerState struct {
	IP              string
	PubKey          string
	KernelInterface bool
	FQDN            string
}

// SignalState contains the latest state of a signal connection
type SignalState struct {
	URL       string
	Connected bool
}

// ManagementState contains the latest state of a management connection
type ManagementState struct {
	URL       string
	Connected bool
}

// FullStatus contains the full state held by the Status instance
type FullStatus struct {
	Peers           []PeerState
	ManagementState ManagementState
	SignalState     SignalState
	LocalPeerState  LocalPeerState
}

// Status holds a state of peers, signal and management connections
type Status struct {
	mux          sync.Mutex
	peers        map[string]PeerState
	changeNotify map[string]chan struct{}
	signal       SignalState
	management   ManagementState
	localPeer    LocalPeerState
}

// NewRecorder returns a new Status instance
func NewRecorder() *Status {
	return &Status{
		peers:        make(map[string]PeerState),
		changeNotify: make(map[string]chan struct{}),
	}
}

// AddPeer adds peer to Daemon status map
func (d *Status) AddPeer(peerPubKey string) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	_, ok := d.peers[peerPubKey]
	if ok {
		return errors.New("peer already exist")
	}
	d.peers[peerPubKey] = PeerState{PubKey: peerPubKey}
	return nil
}

// GetPeer adds peer to Daemon status map
func (d *Status) GetPeer(peerPubKey string) (PeerState, error) {
	d.mux.Lock()
	defer d.mux.Unlock()

	state, ok := d.peers[peerPubKey]
	if !ok {
		return PeerState{}, errors.New("peer not found")
	}
	return state, nil
}

// RemovePeer removes peer from Daemon status map
func (d *Status) RemovePeer(peerPubKey string) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	_, ok := d.peers[peerPubKey]
	if ok {
		delete(d.peers, peerPubKey)
		return nil
	}

	return errors.New("no peer with to remove")
}

// UpdatePeerState updates peer status
func (d *Status) UpdatePeerState(receivedState PeerState) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	peerState, ok := d.peers[receivedState.PubKey]
	if !ok {
		return errors.New("peer doesn't exist")
	}

	if receivedState.IP != "" {
		peerState.IP = receivedState.IP
	}

	if receivedState.ConnStatus != peerState.ConnStatus {
		peerState.ConnStatus = receivedState.ConnStatus
		peerState.ConnStatusUpdate = receivedState.ConnStatusUpdate
		peerState.Direct = receivedState.Direct
		peerState.Relayed = receivedState.Relayed
		peerState.LocalIceCandidateType = receivedState.LocalIceCandidateType
		peerState.RemoteIceCandidateType = receivedState.RemoteIceCandidateType
	}

	d.peers[receivedState.PubKey] = peerState

	ch, found := d.changeNotify[receivedState.PubKey]
	if found && ch != nil {
		close(ch)
		d.changeNotify[receivedState.PubKey] = nil
	}

	return nil
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

// UpdateLocalPeerState updates local peer status
func (d *Status) UpdateLocalPeerState(localPeerState LocalPeerState) {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.localPeer = localPeerState
}

// CleanLocalPeerState cleans local peer status
func (d *Status) CleanLocalPeerState() {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.localPeer = LocalPeerState{}
}

// MarkManagementDisconnected sets ManagementState to disconnected
func (d *Status) MarkManagementDisconnected(managementURL string) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.management = ManagementState{
		URL:       managementURL,
		Connected: false,
	}
}

// MarkManagementConnected sets ManagementState to connected
func (d *Status) MarkManagementConnected(managementURL string) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.management = ManagementState{
		URL:       managementURL,
		Connected: true,
	}
}

// MarkSignalDisconnected sets SignalState to disconnected
func (d *Status) MarkSignalDisconnected(signalURL string) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.signal = SignalState{
		signalURL,
		false,
	}
}

// MarkSignalConnected sets SignalState to connected
func (d *Status) MarkSignalConnected(signalURL string) {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.signal = SignalState{
		signalURL,
		true,
	}
}

// GetFullStatus gets full status
func (d *Status) GetFullStatus() FullStatus {
	d.mux.Lock()
	defer d.mux.Unlock()

	fullStatus := FullStatus{
		ManagementState: d.management,
		SignalState:     d.signal,
		LocalPeerState:  d.localPeer,
	}

	for _, status := range d.peers {
		fullStatus.Peers = append(fullStatus.Peers, status)
	}

	return fullStatus
}
