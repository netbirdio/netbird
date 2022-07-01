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

// NewStatus returns a new Status instance
func NewStatus() *Status {
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

// GetPeerStatus gets peer status
func (d *Status) GetPeerStatus(peerPubKey string) (PeerState, error) {
	d.mux.Lock()
	defer d.mux.Unlock()

	peerState, ok := d.peers[peerPubKey]
	if !ok {
		return PeerState{}, errors.New("peer doesn't exist")
	}

	return peerState, nil
}

// UpdatePeerStatus updates peer status
func (d *Status) UpdatePeerStatus(peerState PeerState) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	_, ok := d.peers[peerState.PubKey]
	if !ok {
		return errors.New("peer doesn't exist")
	}

	d.peers[peerState.PubKey] = peerState

	return nil
}

// UpdateLocalPeerStatus updates local peer status
func (d *Status) UpdateLocalPeerStatus(localPeerState LocalPeerState) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.localPeer = localPeerState

	return nil
}

// UpdateSignalStatus updates signal status
func (d *Status) UpdateSignalStatus(signalState SignalState) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.signal = signalState

	return nil
}

// UpdateManagementStatus updates management status
func (d *Status) UpdateManagementStatus(managementState ManagementState) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.management = managementState

	return nil
}

// GetStatus gets full status
func (d *Status) GetStatus() FullStatus {
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
