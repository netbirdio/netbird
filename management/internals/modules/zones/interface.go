package zones

import (
	"context"
)

type Manager interface {
	GetAllZones(ctx context.Context, accountID, userID string) ([]*Zone, error)
	GetZone(ctx context.Context, accountID, userID, zone string) (*Zone, error)
	CreateZone(ctx context.Context, accountID, userID string, zone *Zone) (*Zone, error)
	UpdateZone(ctx context.Context, accountID, userID string, zone *Zone) (*Zone, error)
	DeleteZone(ctx context.Context, accountID, userID, zoneID string) error
}
