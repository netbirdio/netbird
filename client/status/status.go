package status

import (
	"github.com/pion/ice/v2"
	"sync"
	"time"
)

type PeerState struct {
	IP               string
	PubKey           string
	ConnStatus       string
	ConnStatusUpdate time.Time
	Relayed          bool
	Direct           bool
	IceCandidateType ice.CandidateType
}

type SignalState struct {
	URL       string
	Connected bool
}

type ManagementState struct {
	URL       string
	Connected bool
}

type FullStatus struct {
	Peers           []PeerState
	ManagementState ManagementState
	SignalState     SignalState
}

type Status struct {
	mux        sync.Mutex
	Peers      map[string]PeerState
	Signal     SignalState
	Management ManagementState
}

func NewStatus() *Status {
	return &Status{
		Peers: make(map[string]PeerState),
	}
}

// AddPeer adds peer to Daemon status map
func (d *Status) AddPeer(peerState PeerState) error {
	d.mux.Lock()
	defer d.mux.Unlock()
	d.Peers[peerState.PubKey] = peerState
	return nil
}

// RemovePeer removes peer from Daemon status map
func (d *Status) RemovePeer(peerState PeerState) error {
	d.mux.Lock()
	defer d.mux.Unlock()
	delete(d.Peers, peerState.PubKey)
	return nil
}

// UpdatePeerStatus updates peer status
func (d *Status) UpdatePeerStatus(peerState PeerState) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.Peers[peerState.PubKey] = peerState

	return nil
}

// UpdateSignalStatus updates signal status
func (d *Status) UpdateSignalStatus(signalState SignalState) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.Signal = signalState

	return nil
}

// UpdateManagementStatus updates management status
func (d *Status) UpdateManagementStatus(managementState ManagementState) error {
	d.mux.Lock()
	defer d.mux.Unlock()

	d.Management = managementState

	return nil
}

// GetStatus gets full status
func (d *Status) GetStatus() FullStatus {
	d.mux.Lock()
	defer d.mux.Unlock()

	fullStatus := FullStatus{
		ManagementState: d.Management,
		SignalState:     d.Signal,
	}

	for _, status := range d.Peers {
		fullStatus.Peers = append(fullStatus.Peers, status)
	}

	return fullStatus
}
