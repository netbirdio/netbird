package store

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	peerTypes "github.com/netbirdio/netbird/management/refactor/resources/peers/types"
	settingsTypes "github.com/netbirdio/netbird/management/refactor/resources/settings/types"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

type Store interface {
	AcquireAccountLock(id string) func()
	AcquireGlobalLock() func()
	LoadAccount(id string) error
	WriteAccount(id string) error
	GetLicense() string
	FindPeerByPubKey(pubKey string) (peerTypes.Peer, error)
	FindPeerByID(id string) (peerTypes.Peer, error)
	FindAllPeersInAccount(id string) ([]peerTypes.Peer, error)
	UpdatePeer(peer peerTypes.Peer) error
	FindSettings(accountID string) (settingsTypes.Settings, error)
}

type DefaultStore interface {
	Store
}

type StoreEngine string

func getStoreEngineFromEnv() StoreEngine {
	// NETBIRD_STORE_ENGINE supposed to be used in tests. Otherwise rely on the config file.
	kind, ok := os.LookupEnv("NETBIRD_STORE_ENGINE")
	if !ok {
		return SqliteStoreEngine
	}

	value := StoreEngine(strings.ToLower(kind))

	if value == PostgresStoreEngine || value == SqliteStoreEngine {
		return value
	}

	return SqliteStoreEngine
}

func NewDefaultStore(kind StoreEngine, dataDir string, metrics telemetry.AppMetrics) (DefaultStore, error) {
	if kind == "" {
		// fallback to env. Normally this only should be used from tests
		kind = getStoreEngineFromEnv()
	}
	switch kind {
	case PostgresStoreEngine:
		log.Info("using JSON file store engine")
		return NewDefaultPostgresStore(), nil
	case SqliteStoreEngine:
		log.Info("using SQLite store engine")
		return NewDefaultSqliteStore(dataDir, metrics)
	default:
		return nil, fmt.Errorf("unsupported kind of store %s", kind)
	}
}
