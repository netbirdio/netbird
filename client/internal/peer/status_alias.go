package peer

import "github.com/netbirdio/netbird/client/internal/peer/status"

// Transitional aliases re-exporting the peer status recorder from its own
// package. Callers are being migrated to reference the status package
// directly; these aliases will be removed once the migration completes.
type (
	Status                   = status.Recorder
	State                    = status.State
	ConnStatus               = status.ConnStatus
	FullStatus               = status.FullStatus
	RouterState              = status.RouterState
	LocalPeerState           = status.LocalPeerState
	SignalState              = status.SignalState
	ManagementState          = status.ManagementState
	RosenpassState           = status.RosenpassState
	NSGroupState             = status.NSGroupState
	ResolvedDomainInfo       = status.ResolvedDomainInfo
	StatusChangeSubscription = status.StatusChangeSubscription
	EventQueue               = status.EventQueue
	EventSubscription        = status.EventSubscription
	WGIfaceStatus            = status.WGIfaceStatus
	Listener                 = status.Listener
	EventListener            = status.EventListener
)

const (
	StatusIdle       = status.StatusIdle
	StatusConnecting = status.StatusConnecting
	StatusConnected  = status.StatusConnected
)

var (
	NewRecorder = status.NewRecorder
)
