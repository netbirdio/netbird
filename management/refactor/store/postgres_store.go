package store

import (
	"github.com/netbirdio/netbird/management/refactor/peers"
	"github.com/netbirdio/netbird/management/refactor/settings"
)

const (
	PostgresStoreEngine StoreEngine = "postgres"
)

type DefaultPostgresStore struct {
}

func (s *DefaultPostgresStore) FindSettings(accountID string) (*settings.Settings, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultPostgresStore) FindPeerByPubKey(pubKey string) (*peers.Peer, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultPostgresStore) FindPeerByID(id string) (*peers.Peer, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultPostgresStore) FindAllPeersInAccount(id string) ([]*peers.Peer, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultPostgresStore) UpdatePeer(peer peers.Peer) error {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultPostgresStore) GetLicense() string {
	// TODO implement me
	panic("implement me")
}

func NewDefaultPostgresStore() *DefaultPostgresStore {
	return &DefaultPostgresStore{}
}

func (s *DefaultPostgresStore) GetEngine() StoreEngine {
	return PostgresStoreEngine
}
