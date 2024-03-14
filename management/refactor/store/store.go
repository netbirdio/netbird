package store

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/refactor/peers"
	"github.com/netbirdio/netbird/management/refactor/settings"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

type Store interface {
	GetLicense() string
	FindPeerByPubKey(pubKey string) (peers.Peer, error)
	FindPeerByID(id string) (peers.Peer, error)
	FindAllPeersInAccount(id string) ([]peers.Peer, error)
	UpdatePeer(peer peers.Peer) error
	FindSettings(accountID string) (settings.Settings, error)
}

type DefaultStore interface {
	GetLicense() string
	FindPeerByPubKey(pubKey string) (peers.Peer, error)
	FindPeerByID(id string) (peers.Peer, error)
	FindAllPeersInAccount(id string) ([]peers.Peer, error)
	UpdatePeer(peer peers.Peer) error
	FindSettings(accountID string) (settings.Settings, error)
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
