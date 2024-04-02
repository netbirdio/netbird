package validator

import (
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/peer"
)

type IntegratedValidator interface {
	ValidateExtraSettings(newExtraSettings *account.ExtraSettings, oldExtraSettings *account.ExtraSettings, peers map[string]*peer.Peer, userID string, accountID string) error
	ValidatePeer(update *peer.Peer, peer *peer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *account.ExtraSettings) (*peer.Peer, error)
	PreparePeer(accountID string, peer *peer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) *peer.Peer
	IsNotValidPeer(accountID string, peer *peer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) (bool, bool)
	GetValidatedPeers(accountID string, groups map[string]*group.Group, peers map[string]*peer.Peer, extraSettings *account.ExtraSettings) (map[string]struct{}, error)
	PeerDeleted(accountID, peerID string) error
	SetPeerInvalidationListener(fn func(accountID string))
	Stop()
}
