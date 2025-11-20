package manager

import (
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/server/store"
)

type Repository interface {
	Store() store.Store
	CreateZone(lockingStrength store.LockingStrength, zone *zones.Zone) error
	UpdateZone(lockingStrength store.LockingStrength, zone *zones.Zone) error
	DeleteZone(lockingStrength store.LockingStrength, zone *zones.Zone) error
	GetZoneByID(lockingStrength store.LockingStrength, accountID, zoneID string) (*zones.Zone, error)
	GetAccountZones(lockingStrength store.LockingStrength, accountID string) ([]*zones.Zone, error)
}

type repository struct {
	store *store.SqlStore
}

func NewRepository(s *store.SqlStore) Repository {
	return &repository{store: s}
}

func (r *repository) Store() store.Store {
	//TODO implement me
	panic("implement me")
}

func (r *repository) CreateZone(lockingStrength store.LockingStrength, zone *zones.Zone) error {
	//TODO implement me
	panic("implement me")
}

func (r *repository) UpdateZone(lockingStrength store.LockingStrength, zone *zones.Zone) error {
	//TODO implement me
	panic("implement me")
}

func (r *repository) DeleteZone(lockingStrength store.LockingStrength, zone *zones.Zone) error {
	//TODO implement me
	panic("implement me")
}

func (r *repository) GetZoneByID(lockingStrength store.LockingStrength, accountID, zoneID string) (*zones.Zone, error) {
	//TODO implement me
	panic("implement me")
}

func (r *repository) GetAccountZones(lockingStrength store.LockingStrength, accountID string) ([]*zones.Zone, error) {
	//TODO implement me
	panic("implement me")
}
