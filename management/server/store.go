package server

import (
	"fmt"
	"os"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

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
	SaveUserLastLogin(accountID, userID string, lastLogin time.Time) error
	// Close should close the store persisting all unsaved data.
	Close() error
	// GetStoreKind should return StoreKind of the current store implementation.
	// This is also a method of metrics.DataSource interface.
	GetStoreKind() StoreKind
}

type StoreKind string

const (
	FileStoreKind   StoreKind = "JsonFile"
	SqliteStoreKind StoreKind = "Sqlite"
)

func GetStoreKindFromEnv() StoreKind {
	kind, ok := os.LookupEnv("NETBIRD_STORE_KIND")
	if !ok {
		return FileStoreKind
	}

	value := StoreKind(kind)

	if value == FileStoreKind || value == SqliteStoreKind {
		return value
	}

	return FileStoreKind
}

func NewStore(kind StoreKind, dataDir string, metrics telemetry.AppMetrics) (Store, error) {
	if kind == "" {
		// fallback to env. Normally this only should be used from tests
		kind = GetStoreKindFromEnv()
	}
	switch kind {
	case FileStoreKind:
		return NewFileStore(dataDir, metrics)
	case SqliteStoreKind:
		return NewSqliteStore(dataDir, metrics)
	default:
		return nil, fmt.Errorf("unsupported kind of store %s", kind)
	}
}

func NewStoreFromJson(dataDir string, metrics telemetry.AppMetrics) (Store, error) {
	fstore, err := NewFileStore(dataDir, nil)
	if err != nil {
		return nil, err
	}

	kind := GetStoreKindFromEnv()

	switch kind {
	case FileStoreKind:
		return fstore, nil
	case SqliteStoreKind:
		return NewSqliteStoreFromFileStore(fstore, dataDir, metrics)
	default:
		return nil, fmt.Errorf("unsupported kind of store %s", kind)
	}

}
