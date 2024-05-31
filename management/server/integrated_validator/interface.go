package integrated_validator

import (
	"github.com/netbirdio/netbird/management/server/account"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

// IntegratedValidator interface exists to avoid the circle dependencies
type IntegratedValidator interface {
	ValidateExtraSettings(newExtraSettings *account.ExtraSettings, oldExtraSettings *account.ExtraSettings, peers map[string]*nbpeer.Peer, userID string, accountID string) error
	ValidatePeer(update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *account.ExtraSettings) (*nbpeer.Peer, error)
	PreparePeer(accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) *nbpeer.Peer
	IsNotValidPeer(accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) (bool, bool, error)
	GetValidatedPeers(accountID string, groups map[string]*nbgroup.Group, peers map[string]*nbpeer.Peer, extraSettings *account.ExtraSettings) (map[string]struct{}, error)
	PeerDeleted(accountID, peerID string) error
	SetPeerInvalidationListener(fn func(accountID string))
	Stop()
}
