package proxy

import "time"

// Capabilities describes what a proxy can handle, as reported via gRPC.
// Nil fields mean the proxy never reported this capability.
type Capabilities struct {
	// SupportsCustomPorts indicates whether this proxy can bind arbitrary
	// ports for TCP/UDP services. TLS uses SNI routing and is not gated.
	SupportsCustomPorts *bool
	// RequireSubdomain indicates whether a subdomain label is required in
	// front of the cluster domain.
	RequireSubdomain *bool
	// SupportsCrowdsec indicates whether this proxy has CrowdSec configured.
	SupportsCrowdsec *bool
}

// Proxy represents a reverse proxy instance
type Proxy struct {
	ID             string    `gorm:"primaryKey;type:varchar(255)"`
	SessionID      string    `gorm:"type:varchar(36)"`
	ClusterAddress string    `gorm:"type:varchar(255);not null;index:idx_proxy_cluster_status"`
	IPAddress      string    `gorm:"type:varchar(45)"`
	LastSeen       time.Time `gorm:"not null;index:idx_proxy_last_seen"`
	ConnectedAt    *time.Time
	DisconnectedAt *time.Time
	Status         string       `gorm:"type:varchar(20);not null;index:idx_proxy_cluster_status"`
	Capabilities   Capabilities `gorm:"embedded"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (Proxy) TableName() string {
	return "proxies"
}

// Cluster represents a group of proxy nodes serving the same address.
type Cluster struct {
	Address          string
	ConnectedProxies int
}
