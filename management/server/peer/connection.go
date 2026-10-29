package peer

import "time"

// ManagementInstance is one running management process. Its LastSeen is written only
// with the database clock, so every comparison against it uses a single time source.
type ManagementInstance struct {
	// ID is random per process and never reused.
	ID string `gorm:"primaryKey"`
	// Hostname is informational.
	Hostname  string
	StartedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
	LastSeen  time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
}

// Connection is a peer's liveness record. It is created with the peer and lives until the
// peer is deleted. A peer counts as connected while InstanceID names a fresh management
// instance.
type Connection struct {
	PeerID    string `gorm:"primaryKey"`
	AccountID string `gorm:"not null;index"`
	// InstanceID is the management instance holding the peer's sync stream, nil while no
	// instance holds it.
	InstanceID *string `gorm:"index"`
	// SessionStartedAt is the fencing token of the latest sync stream that held the peer,
	// in Unix nanoseconds. Releasing the connection regardless of its session advances it by
	// one, so the released session cannot be re-registered.
	SessionStartedAt int64 `gorm:"not null;default:0"`
	// LastSeen is the last time the peer was observed alive, apart from the heartbeat of
	// the instance holding it. Nil when it never was.
	LastSeen *time.Time
}

// TableName returns the table that stores peer connections.
func (Connection) TableName() string {
	return "peer_connections"
}
