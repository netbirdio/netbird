package types

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// NetworkMapRecord stores a precomputed network map for a peer
// MapJSON is stored as jsonb (Postgres), json (MySQL), or text (SQLite)
type NetworkMapRecord struct {
	PeerID    string         `gorm:"primaryKey"`
	AccountID string         `gorm:"index"`
	MapJSON   datatypes.JSON `gorm:"type:jsonb"` // GORM will use the right type for your DB
	Serial    uint64
	UpdatedAt time.Time
}

// TableName sets the table name for GORM
// This ensures the table is named consistently across all supported databases.
func (NetworkMapRecord) TableName() string {
	return "network_map_records"
}

// SaveNetworkMapRecord stores or updates a NetworkMapRecord in the database
func SaveNetworkMapRecord(db *gorm.DB, record *NetworkMapRecord) error {
	return db.Save(record).Error
}

// GetNetworkMapRecord retrieves a NetworkMapRecord by peer ID
func GetNetworkMapRecord(db *gorm.DB, peerID string) (*NetworkMapRecord, error) {
	var record NetworkMapRecord
	err := db.First(&record, "peer_id = ?", peerID).Error
	if err != nil {
		return nil, err
	}
	return &record, nil
}
