package types

import "time"

// Copy PeerStatus
func (p *PeerStatus) Copy() *PeerStatus {
	return &PeerStatus{
		LastSeen:         p.LastSeen,
		Connected:        p.Connected,
		LoginExpired:     p.LoginExpired,
		RequiresApproval: p.RequiresApproval,
	}
}

type PeerStatus struct { //nolint:revive
	// LastSeen is the last time peer was connected to the management service
	LastSeen time.Time
	// Connected indicates whether peer is connected to the management service or not
	Connected bool
	// LoginExpired
	LoginExpired bool
	// RequiresApproval indicates whether peer requires approval or not
	RequiresApproval bool
}
