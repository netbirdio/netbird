package store

import (
	peerTypes "github.com/netbirdio/netbird/management/refactor/resources/peers/types"
	settingsTypes "github.com/netbirdio/netbird/management/refactor/resources/settings/types"
)

const (
	PostgresStoreEngine StoreEngine = "postgres"
)

type DefaultPostgresStore struct {
}

func (s *DefaultPostgresStore) FindSettings(accountID string) (settingsTypes.Settings, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultPostgresStore) FindPeerByPubKey(pubKey string) (peerTypes.Peer, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultPostgresStore) FindPeerByID(id string) (peerTypes.Peer, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultPostgresStore) FindAllPeersInAccount(id string) ([]peerTypes.Peer, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultPostgresStore) UpdatePeer(peer peerTypes.Peer) error {
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
