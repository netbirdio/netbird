package status

import (
	"errors"
	"github.com/pion/ice/v2"
	"sync"
	"time"
)

// PeerState contains the latest state of a peer
type PeerState struct {
	IP               string
	PubKey           string
	ConnStatus       string
	ConnStatusUpdate time.Time
	Relayed          bool
	Direct           bool
	IceCandidateType ice.CandidateType
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

// FullStatus continas the full state holded by the Status instance
type FullStatus struct {
	Peers           []PeerState
	ManagementState ManagementState
	SignalState     SignalState
}

// Status a instance to hold state of peers, signal and managment connections
type Status struct {
	mux        sync.Mutex
	peers      map[string]PeerState
	signal     SignalState
	management ManagementState
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
	d.peers[peerPubKey] = PeerState{}
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
	}

	for _, status := range d.peers {
		fullStatus.Peers = append(fullStatus.Peers, status)
	}

	return fullStatus
}
