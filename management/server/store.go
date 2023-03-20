package server

type Store interface {
	GetAllAccounts() []*Account
	GetAccount(accountID string) (*Account, error)
	GetAccountByUser(userID string) (*Account, error)
	GetAccountByPeerPubKey(peerKey string) (*Account, error)
	GetAccountByPeerID(peerID string) (*Account, error)
	GetAccountBySetupKey(setupKey string) (*Account, error) // todo use key hash later
	GetAccountByPrivateDomain(domain string) (*Account, error)
	GetTokenIDByHashedToken(secret string) (string, error)
	GetUserByTokenID(tokenID string) (*User, error)
	SaveAccount(account *Account) error
	DeleteHashedPAT2TokenIDIndex(hashedToken string) error
	DeleteTokenID2UserIDIndex(tokenID string) error
	GetInstallationID() string
	SaveInstallationID(ID string) error
	// AcquireAccountLock should attempt to acquire account lock and return a function that releases the lock
	AcquireAccountLock(accountID string) func()
	// AcquireGlobalLock should attempt to acquire a global lock and return a function that releases the lock
	AcquireGlobalLock() func()
	SavePeerStatus(accountID, peerID string, status PeerStatus) error
	// Close should close the store persisting all unsaved data.
	Close() error
}
