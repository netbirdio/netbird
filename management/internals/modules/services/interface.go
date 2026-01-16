package services

import (
	"context"
)

type Manager interface {
	GetAllServices(ctx context.Context, accountID, userID string) ([]*Service, error)
	GetService(ctx context.Context, accountID, userID, serviceID string) (*Service, error)
	CreateService(ctx context.Context, accountID, userID string, service *Service) (*Service, error)
	UpdateService(ctx context.Context, accountID, userID string, service *Service) (*Service, error)
	DeleteService(ctx context.Context, accountID, userID, serviceID string) error
}
