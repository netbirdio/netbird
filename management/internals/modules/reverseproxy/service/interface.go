package service

//go:generate go run github.com/golang/mock/mockgen -package service -destination=interface_mock.go -source=./interface.go -build_flags=-mod=mod

import (
	"context"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
)

type Manager interface {
	GetActiveClusters(ctx context.Context, accountID, userID string) ([]proxy.Cluster, error)
	DeleteAccountCluster(ctx context.Context, accountID, userID, clusterAddress string) error
	GetAllServices(ctx context.Context, accountID, userID string) ([]*Service, error)
	GetService(ctx context.Context, accountID, userID, serviceID string) (*Service, error)
	CreateService(ctx context.Context, accountID, userID string, service *Service) (*Service, error)
	UpdateService(ctx context.Context, accountID, userID string, service *Service) (*Service, error)
	DeleteService(ctx context.Context, accountID, userID, serviceID string) error
	DeleteAllServices(ctx context.Context, accountID, userID string) error
	SetCertificateIssuedAt(ctx context.Context, accountID, serviceID string) error
	SetStatus(ctx context.Context, accountID, serviceID string, status Status) error
	ReloadAllServicesForAccount(ctx context.Context, accountID string) error
	ReloadService(ctx context.Context, accountID, serviceID string) error
	GetGlobalServices(ctx context.Context) ([]*Service, error)
	GetServiceByID(ctx context.Context, accountID, serviceID string) (*Service, error)
	GetAccountServices(ctx context.Context, accountID string) ([]*Service, error)
	GetServiceIDByTargetID(ctx context.Context, accountID string, resourceID string) (string, error)
	CreateServiceFromPeer(ctx context.Context, accountID, peerID string, req *ExposeServiceRequest) (*ExposeServiceResponse, error)
	RenewServiceFromPeer(ctx context.Context, accountID, peerID, serviceID string) error
	StopServiceFromPeer(ctx context.Context, accountID, peerID, serviceID string) error
	StartExposeReaper(ctx context.Context)
	GetServiceByDomain(ctx context.Context, domain string) (*Service, error)
}
