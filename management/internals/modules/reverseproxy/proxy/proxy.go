package proxy

import "time"

// Proxy represents a reverse proxy instance
type Proxy struct {
	ID             string    `gorm:"primaryKey;type:varchar(255)"`
	ClusterAddress string    `gorm:"type:varchar(255);not null;index:idx_proxy_cluster_status"`
	IPAddress      string    `gorm:"type:varchar(45)"`
	LastSeen       time.Time `gorm:"not null;index:idx_proxy_last_seen"`
	ConnectedAt    *time.Time
	DisconnectedAt *time.Time
	Status         string `gorm:"type:varchar(20);not null;index:idx_proxy_cluster_status"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (Proxy) TableName() string {
	return "proxies"
}
