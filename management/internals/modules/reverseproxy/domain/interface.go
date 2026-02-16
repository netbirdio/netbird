package domain

import (
	"context"
)

type Manager interface {
	GetDomains(ctx context.Context, accountID, userID string) ([]*Domain, error)
	CreateDomain(ctx context.Context, accountID, userID, domainName, targetCluster string) (*Domain, error)
	DeleteDomain(ctx context.Context, accountID, userID, domainID string) error
	ValidateDomain(ctx context.Context, accountID, userID, domainID string)
}
