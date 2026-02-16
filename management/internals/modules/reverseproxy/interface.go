package reverseproxy

//go:generate go run github.com/golang/mock/mockgen -package reverseproxy -destination=interface_mock.go -source=./interface.go -build_flags=-mod=mod

import (
	"context"
)

type Manager interface {
	GetAllServices(ctx context.Context, accountID, userID string) ([]*Service, error)
	GetService(ctx context.Context, accountID, userID, serviceID string) (*Service, error)
	CreateService(ctx context.Context, accountID, userID string, service *Service) (*Service, error)
	UpdateService(ctx context.Context, accountID, userID string, service *Service) (*Service, error)
	DeleteService(ctx context.Context, accountID, userID, serviceID string) error
	SetCertificateIssuedAt(ctx context.Context, accountID, serviceID string) error
	SetStatus(ctx context.Context, accountID, serviceID string, status ProxyStatus) error
	ReloadAllServicesForAccount(ctx context.Context, accountID string) error
	ReloadService(ctx context.Context, accountID, serviceID string) error
	GetGlobalServices(ctx context.Context) ([]*Service, error)
	GetServiceByID(ctx context.Context, accountID, serviceID string) (*Service, error)
	GetAccountServices(ctx context.Context, accountID string) ([]*Service, error)
	GetServiceIDByTargetID(ctx context.Context, accountID string, resourceID string) (string, error)
}
