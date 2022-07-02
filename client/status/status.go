package status

import (
	"errors"
	"sync"
	"time"
)

// PeerState contains the latest state of a peer
type PeerState struct {
	IP                     string
	PubKey                 string
	ConnStatus             string
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
	mux        sync.Mutex
	peers      map[string]PeerState
	signal     SignalState
	management ManagementState
	localPeer  LocalPeerState
}

// NewRecorder returns a new Status instance
func NewRecorder() *Status {
	return &Status{
		peers: make(map[string]PeerState),
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

	return nil
}

// UpdateLocalPeerState updates local peer status
func (d *Status) UpdateLocalPeerState(localPeerState LocalPeerState) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.localPeer = localPeerState

	return nil
}

// UpdateSignalState updates signal status
func (d *Status) UpdateSignalState(signalState SignalState) {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.signal = signalState
}

// UpdateManagementState updates management status
func (d *Status) UpdateManagementState(managementState ManagementState) {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.management = managementState
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
