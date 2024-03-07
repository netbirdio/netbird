package integrated_approval

import (
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

// IntegratedApproval interface exists to avoid the circle dependencies
type IntegratedApproval interface {
	PreparePeer(accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) *nbpeer.Peer
	IsRequiresApproval(accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) (bool, bool)
	ApprovedPeersList(id string) (map[string]struct{}, error)
	Stop()
}
