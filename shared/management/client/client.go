package client

import (
	"context"
	"io"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// Client is the interface for the management service client.
type Client interface {
	io.Closer
	Sync(ctx context.Context, sysInfo *system.Info, msgHandler func(msg *proto.SyncResponse) error) error
	Job(ctx context.Context, msgHandler func(msg *proto.JobRequest) *proto.JobResponse) error
	Register(setupKey string, jwtToken string, sysInfo *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error)
	Login(sysInfo *system.Info, sshKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error)
	GetDeviceAuthorizationFlow() (*proto.DeviceAuthorizationFlow, error)
	GetPKCEAuthorizationFlow() (*proto.PKCEAuthorizationFlow, error)
	GetNetworkMap(sysInfo *system.Info) (*proto.NetworkMap, error)
	GetServerURL() string
	// IsHealthy returns the current connection status without blocking.
	// Used by the engine to monitor connectivity in the background.
	IsHealthy() bool
	// HealthCheck actively probes the management server and returns an error if unreachable.
	// Used to validate connectivity before committing configuration changes.
	HealthCheck() error
	SyncMeta(sysInfo *system.Info) error
	// SyncPeerConnections sends the peer's current per-peer connection map
	// to the management server as a unary RPC. Phase 3.7i of #5989.
	SyncPeerConnections(ctx context.Context, m *proto.PeerConnectionMap) error
	// SetEffectiveConnConfig records the engine-resolved connection mode/
	// timeouts to report in subsequent Sync/Login/SyncMeta PeerSystemMeta.
	// Phase 3.7i of #5989.
	SetEffectiveConnConfig(eff EffectiveConnConfig)
	Logout() error
	CreateExpose(ctx context.Context, req ExposeRequest) (*ExposeResponse, error)
	RenewExpose(ctx context.Context, domain string) error
	StopExpose(ctx context.Context, domain string) error
}
