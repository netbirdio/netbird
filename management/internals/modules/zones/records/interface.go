package records

import (
	"context"
)

type Manager interface {
	GetAllRecords(ctx context.Context, accountID, userID, zoneID string) ([]*Record, error)
	GetRecord(ctx context.Context, accountID, userID, zoneID, recordID string) (*Record, error)
	CreateRecord(ctx context.Context, accountID, userID, zoneID string, record *Record) (*Record, error)
	UpdateRecord(ctx context.Context, accountID, userID, zoneID string, record *Record) (*Record, error)
	DeleteRecord(ctx context.Context, accountID, userID, zoneID, recordID string) error
}
