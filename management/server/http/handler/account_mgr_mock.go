package handler

type MockAccountManager struct {
}

// GetOrCreateAccountByUser(userId, domain string) (*Account, error)
// GetAccountByUser(userId string) (*Account, error)
// AddSetupKey(accountId string, keyName string, keyType SetupKeyType, expiresIn *util.Duration) (*SetupKey, error)
// RevokeSetupKey(accountId string, keyId string) (*SetupKey, error)
// RenameSetupKey(accountId string, keyId string, newName string) (*SetupKey, error)
// GetAccountById(accountId string) (*Account, error)
// GetAccountByUserOrAccountId(userId, accountId, domain string) (*Account, error)
// AccountExists(accountId string) (*bool, error)
// AddAccount(accountId, userId, domain string) (*Account, error)
// GetPeer(peerKey string) (*Peer, error)
// MarkPeerConnected(peerKey string, connected bool) error
// RenamePeer(accountId string, peerKey string, newName string) (*Peer, error)
// DeletePeer(accountId string, peerKey string) (*Peer, error)
// GetPeerByIP(accountId string, peerIP string) (*Peer, error)
// GetNetworkMap(peerKey string) (*NetworkMap, error)
// AddPeer(setupKey string, peer *Peer) (*Peer, error)
