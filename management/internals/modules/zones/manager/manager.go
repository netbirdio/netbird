package manager

import (
	"context"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/server/account"
)

type managerImpl struct {
	repo           Repository
	accountManager account.Manager
}

func NewManager(repo Repository, accountManager account.Manager) zones.Manager {
	return &managerImpl{
		repo:           repo,
		accountManager: accountManager,
	}
}

func (m managerImpl) GetAllZones(ctx context.Context, accountID, userID string) ([]*zones.Zone, error) {
	//TODO implement me
	panic("implement me")
}

func (m managerImpl) GetZone(ctx context.Context, accountID, userID, zone string) (*zones.Zone, error) {
	//TODO implement me
	panic("implement me")
}

func (m managerImpl) CreateZone(ctx context.Context, userID string, zone *zones.Zone) (*zones.Zone, error) {
	//TODO implement me
	panic("implement me")
}

func (m managerImpl) UpdateZone(ctx context.Context, userID string, zone *zones.Zone) (*zones.Zone, error) {
	//TODO implement me
	panic("implement me")
}

func (m managerImpl) DeleteZone(ctx context.Context, accountID, userID, zoneID string) error {
	//TODO implement me
	panic("implement me")
}
