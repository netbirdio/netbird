package integrated_approval

import (
	"errors"

	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

var (
	ErrPeerApprovalNotAllowed = errors.New("peer approval is not allowed to enable if has another approval setting for account")
	ErrForceUpdateNotAllowed  = errors.New("force update is not supported with external approval integration")
)

// IntegratedApproval interface exists to avoid the circle dependencies
type IntegratedApproval interface {
	UpdatePeerApprovalSetting(newExtraSettings *account.ExtraSettings, oldExtraSettings *account.ExtraSettings, peers map[string]*nbpeer.Peer, userID string, accountID string) error
	ApprovePeer(update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *account.ExtraSettings) (*nbpeer.Peer, error)
	PreparePeer(accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) *nbpeer.Peer
	IsRequiresApproval(accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) bool
	GetApprovedPeers(accountID string, peers map[string]*nbpeer.Peer, extraSettings *account.ExtraSettings) (map[string]struct{}, error)
	Stop()
}
