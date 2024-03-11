package integrated_approval

import (
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
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
