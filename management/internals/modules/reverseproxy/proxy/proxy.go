package proxy

import (
	"time"
)

const (
	StatusConnected    = "connected"
	StatusDisconnected = "disconnected"
)

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
	// Private indicates whether this proxy supports inbound access via Wireguard
	// tunnel and netbird-only authentication policies
	Private *bool
}

// Proxy represents a reverse proxy instance
type Proxy struct {
	ID             string    `gorm:"primaryKey;type:varchar(255)"`
	SessionID      string    `gorm:"type:varchar(36)"`
	ClusterAddress string    `gorm:"type:varchar(255);not null;index:idx_proxy_cluster_status"`
	IPAddress      string    `gorm:"type:varchar(45)"`
	AccountID      *string   `gorm:"type:varchar(255);index:idx_proxy_account_id"`
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

// ClusterType is the source of a proxy cluster.
type ClusterType string

const (
	// ClusterTypeAccount is a cluster operated by the account itself (BYOP) —
	// at least one proxy row in the cluster carries a non-NULL account_id.
	ClusterTypeAccount ClusterType = "account"
	// ClusterTypeShared is a cluster operated by NetBird and shared across
	// accounts — all proxy rows in the cluster have account_id IS NULL.
	ClusterTypeShared ClusterType = "shared"
)

// Cluster represents a group of proxy nodes serving the same address.
//
// Online and ConnectedProxies derive from the same 2-min active window
// the rest of the module uses, but Cluster rows are not gated on it —
// the cluster listing surfaces offline clusters too so operators can
// see and clean them up. The 1-hour heartbeat reaper still bounds the
// table eventually.
type Cluster struct {
	ID               string
	Address          string
	Type             ClusterType
	Online           bool
	ConnectedProxies int
	// *bool: nil = no proxy reported the capability; the dashboard renders that as unknown.
	SupportsCustomPorts *bool
	RequireSubdomain    *bool
	SupportsCrowdSec    *bool
	Private             *bool
}
