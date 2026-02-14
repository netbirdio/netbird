package manager

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

const unknownHostPlaceholder = "unknown"

// ClusterDeriver derives the proxy cluster from a domain.
type ClusterDeriver interface {
	DeriveClusterFromDomain(ctx context.Context, accountID, domain string) (string, error)
}

type managerImpl struct {
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager
	proxyGRPCServer    *nbgrpc.ProxyServiceServer
	clusterDeriver     ClusterDeriver
}

// NewManager creates a new service manager.
func NewManager(store store.Store, accountManager account.Manager, permissionsManager permissions.Manager, proxyGRPCServer *nbgrpc.ProxyServiceServer, clusterDeriver ClusterDeriver) reverseproxy.Manager {
	return &managerImpl{
		store:              store,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
		proxyGRPCServer:    proxyGRPCServer,
		clusterDeriver:     clusterDeriver,
	}
}

func (m *managerImpl) GetAllServices(ctx context.Context, accountID, userID string) ([]*reverseproxy.Service, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	services, err := m.store.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get services: %w", err)
	}

	for _, service := range services {
		err = m.replaceHostByLookup(ctx, accountID, service)
		if err != nil {
			return nil, fmt.Errorf("failed to replace host by lookup for service %s: %w", service.ID, err)
		}
	}

	return services, nil
}

func (m *managerImpl) replaceHostByLookup(ctx context.Context, accountID string, service *reverseproxy.Service) error {
	for _, target := range service.Targets {
		switch target.TargetType {
		case reverseproxy.TargetTypePeer:
			peer, err := m.store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, target.TargetId)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to get peer by id %s for service %s: %v", target.TargetId, service.ID, err)
				target.Host = unknownHostPlaceholder
				continue
			}
			target.Host = peer.IP.String()
		case reverseproxy.TargetTypeHost:
			resource, err := m.store.GetNetworkResourceByID(ctx, store.LockingStrengthNone, accountID, target.TargetId)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to get resource by id %s for service %s: %v", target.TargetId, service.ID, err)
				target.Host = unknownHostPlaceholder
				continue
			}
			target.Host = resource.Prefix.Addr().String()
		case reverseproxy.TargetTypeDomain:
			resource, err := m.store.GetNetworkResourceByID(ctx, store.LockingStrengthNone, accountID, target.TargetId)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to get resource by id %s for service %s: %v", target.TargetId, service.ID, err)
				target.Host = unknownHostPlaceholder
				continue
			}
			target.Host = resource.Domain
		case reverseproxy.TargetTypeSubnet:
			// For subnets we do not do any lookups on the resource
		default:
			return fmt.Errorf("unknown target type: %s", target.TargetType)
		}
	}
	return nil
}

func (m *managerImpl) GetService(ctx context.Context, accountID, userID, serviceID string) (*reverseproxy.Service, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	service, err := m.store.GetServiceByID(ctx, store.LockingStrengthNone, accountID, serviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get service: %w", err)
	}

	err = m.replaceHostByLookup(ctx, accountID, service)
	if err != nil {
		return nil, fmt.Errorf("failed to replace host by lookup for service %s: %w", service.ID, err)
	}
	return service, nil
}

func (m *managerImpl) CreateService(ctx context.Context, accountID, userID string, service *reverseproxy.Service) (*reverseproxy.Service, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err := m.initializeServiceForCreate(ctx, accountID, service); err != nil {
		return nil, err
	}

	if err := m.persistNewService(ctx, accountID, service); err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, service.ID, accountID, activity.ServiceCreated, service.EventMeta())

	err = m.replaceHostByLookup(ctx, accountID, service)
	if err != nil {
		return nil, fmt.Errorf("failed to replace host by lookup for service %s: %w", service.ID, err)
	}

	m.proxyGRPCServer.SendServiceUpdateToCluster(service.ToProtoMapping(reverseproxy.Create, "", m.proxyGRPCServer.GetOIDCValidationConfig()), service.ProxyCluster)

	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return service, nil
}

func (m *managerImpl) initializeServiceForCreate(ctx context.Context, accountID string, service *reverseproxy.Service) error {
	if m.clusterDeriver != nil {
		proxyCluster, err := m.clusterDeriver.DeriveClusterFromDomain(ctx, accountID, service.Domain)
		if err != nil {
			log.WithError(err).Warnf("could not derive cluster from domain %s, updates will broadcast to all proxy servers", service.Domain)
			return status.Errorf(status.PreconditionFailed, "could not derive cluster from domain %s: %v", service.Domain, err)
		}
		service.ProxyCluster = proxyCluster
	}

	service.AccountID = accountID
	service.InitNewRecord()

	if err := service.Auth.HashSecrets(); err != nil {
		return fmt.Errorf("hash secrets: %w", err)
	}

	keyPair, err := sessionkey.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate session keys: %w", err)
	}
	service.SessionPrivateKey = keyPair.PrivateKey
	service.SessionPublicKey = keyPair.PublicKey

	return nil
}

func (m *managerImpl) persistNewService(ctx context.Context, accountID string, service *reverseproxy.Service) error {
	return m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err := m.checkDomainAvailable(ctx, transaction, accountID, service.Domain, ""); err != nil {
			return err
		}

		if err := validateTargetReferences(ctx, transaction, accountID, service.Targets); err != nil {
			return err
		}

		if err := transaction.CreateService(ctx, service); err != nil {
			return fmt.Errorf("failed to create service: %w", err)
		}

		return nil
	})
}

func (m *managerImpl) checkDomainAvailable(ctx context.Context, transaction store.Store, accountID, domain, excludeServiceID string) error {
	existingService, err := transaction.GetServiceByDomain(ctx, accountID, domain)
	if err != nil {
		if sErr, ok := status.FromError(err); !ok || sErr.Type() != status.NotFound {
			return fmt.Errorf("failed to check existing service: %w", err)
		}
		return nil
	}

	if existingService != nil && existingService.ID != excludeServiceID {
		return status.Errorf(status.AlreadyExists, "service with domain %s already exists", domain)
	}

	return nil
}

func (m *managerImpl) UpdateService(ctx context.Context, accountID, userID string, service *reverseproxy.Service) (*reverseproxy.Service, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err := service.Auth.HashSecrets(); err != nil {
		return nil, fmt.Errorf("hash secrets: %w", err)
	}

	updateInfo, err := m.persistServiceUpdate(ctx, accountID, service)
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, service.ID, accountID, activity.ServiceUpdated, service.EventMeta())

	if err := m.replaceHostByLookup(ctx, accountID, service); err != nil {
		return nil, fmt.Errorf("failed to replace host by lookup for service %s: %w", service.ID, err)
	}

	m.sendServiceUpdateNotifications(service, updateInfo)
	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return service, nil
}

type serviceUpdateInfo struct {
	oldCluster            string
	domainChanged         bool
	serviceEnabledChanged bool
}

func (m *managerImpl) persistServiceUpdate(ctx context.Context, accountID string, service *reverseproxy.Service) (*serviceUpdateInfo, error) {
	var updateInfo serviceUpdateInfo

	err := m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		existingService, err := transaction.GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, service.ID)
		if err != nil {
			return err
		}

		updateInfo.oldCluster = existingService.ProxyCluster
		updateInfo.domainChanged = existingService.Domain != service.Domain

		if updateInfo.domainChanged {
			if err := m.handleDomainChange(ctx, transaction, accountID, service); err != nil {
				return err
			}
		} else {
			service.ProxyCluster = existingService.ProxyCluster
		}

		m.preserveExistingAuthSecrets(service, existingService)
		m.preserveServiceMetadata(service, existingService)
		updateInfo.serviceEnabledChanged = existingService.Enabled != service.Enabled

		if err := validateTargetReferences(ctx, transaction, accountID, service.Targets); err != nil {
			return err
		}

		if err := transaction.UpdateService(ctx, service); err != nil {
			return fmt.Errorf("update service: %w", err)
		}

		return nil
	})

	return &updateInfo, err
}

func (m *managerImpl) handleDomainChange(ctx context.Context, transaction store.Store, accountID string, service *reverseproxy.Service) error {
	if err := m.checkDomainAvailable(ctx, transaction, accountID, service.Domain, service.ID); err != nil {
		return err
	}

	if m.clusterDeriver != nil {
		newCluster, err := m.clusterDeriver.DeriveClusterFromDomain(ctx, accountID, service.Domain)
		if err != nil {
			log.WithError(err).Warnf("could not derive cluster from domain %s", service.Domain)
		} else {
			service.ProxyCluster = newCluster
		}
	}

	return nil
}

func (m *managerImpl) preserveExistingAuthSecrets(service, existingService *reverseproxy.Service) {
	if service.Auth.PasswordAuth != nil && service.Auth.PasswordAuth.Enabled &&
		existingService.Auth.PasswordAuth != nil && existingService.Auth.PasswordAuth.Enabled &&
		service.Auth.PasswordAuth.Password == "" {
		service.Auth.PasswordAuth = existingService.Auth.PasswordAuth
	}

	if service.Auth.PinAuth != nil && service.Auth.PinAuth.Enabled &&
		existingService.Auth.PinAuth != nil && existingService.Auth.PinAuth.Enabled &&
		service.Auth.PinAuth.Pin == "" {
		service.Auth.PinAuth = existingService.Auth.PinAuth
	}
}

func (m *managerImpl) preserveServiceMetadata(service, existingService *reverseproxy.Service) {
	service.Meta = existingService.Meta
	service.SessionPrivateKey = existingService.SessionPrivateKey
	service.SessionPublicKey = existingService.SessionPublicKey
}

func (m *managerImpl) sendServiceUpdateNotifications(service *reverseproxy.Service, updateInfo *serviceUpdateInfo) {
	oidcCfg := m.proxyGRPCServer.GetOIDCValidationConfig()

	switch {
	case updateInfo.domainChanged && updateInfo.oldCluster != service.ProxyCluster:
		m.proxyGRPCServer.SendServiceUpdateToCluster(service.ToProtoMapping(reverseproxy.Delete, "", oidcCfg), updateInfo.oldCluster)
		m.proxyGRPCServer.SendServiceUpdateToCluster(service.ToProtoMapping(reverseproxy.Create, "", oidcCfg), service.ProxyCluster)
	case !service.Enabled && updateInfo.serviceEnabledChanged:
		m.proxyGRPCServer.SendServiceUpdateToCluster(service.ToProtoMapping(reverseproxy.Delete, "", oidcCfg), service.ProxyCluster)
	case service.Enabled && updateInfo.serviceEnabledChanged:
		m.proxyGRPCServer.SendServiceUpdateToCluster(service.ToProtoMapping(reverseproxy.Create, "", oidcCfg), service.ProxyCluster)
	default:
		m.proxyGRPCServer.SendServiceUpdateToCluster(service.ToProtoMapping(reverseproxy.Update, "", oidcCfg), service.ProxyCluster)
	}
}

// validateTargetReferences checks that all target IDs reference existing peers or resources in the account.
func validateTargetReferences(ctx context.Context, transaction store.Store, accountID string, targets []*reverseproxy.Target) error {
	for _, target := range targets {
		switch target.TargetType {
		case reverseproxy.TargetTypePeer:
			if _, err := transaction.GetPeerByID(ctx, store.LockingStrengthShare, accountID, target.TargetId); err != nil {
				if sErr, ok := status.FromError(err); ok && sErr.Type() == status.NotFound {
					return status.Errorf(status.InvalidArgument, "peer target %q not found in account", target.TargetId)
				}
				return fmt.Errorf("look up peer target %q: %w", target.TargetId, err)
			}
		case reverseproxy.TargetTypeHost, reverseproxy.TargetTypeSubnet, reverseproxy.TargetTypeDomain:
			if _, err := transaction.GetNetworkResourceByID(ctx, store.LockingStrengthShare, accountID, target.TargetId); err != nil {
				if sErr, ok := status.FromError(err); ok && sErr.Type() == status.NotFound {
					return status.Errorf(status.InvalidArgument, "resource target %q not found in account", target.TargetId)
				}
				return fmt.Errorf("look up resource target %q: %w", target.TargetId, err)
			}
		}
	}
	return nil
}

func (m *managerImpl) DeleteService(ctx context.Context, accountID, userID, serviceID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	var service *reverseproxy.Service
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		var err error
		service, err = transaction.GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID)
		if err != nil {
			return err
		}

		if err = transaction.DeleteService(ctx, accountID, serviceID); err != nil {
			return fmt.Errorf("failed to delete service: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	m.accountManager.StoreEvent(ctx, userID, serviceID, accountID, activity.ServiceDeleted, service.EventMeta())

	m.proxyGRPCServer.SendServiceUpdateToCluster(service.ToProtoMapping(reverseproxy.Delete, "", m.proxyGRPCServer.GetOIDCValidationConfig()), service.ProxyCluster)

	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

// SetCertificateIssuedAt sets the certificate issued timestamp to the current time.
// Call this when receiving a gRPC notification that the certificate was issued.
func (m *managerImpl) SetCertificateIssuedAt(ctx context.Context, accountID, serviceID string) error {
	return m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		service, err := transaction.GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID)
		if err != nil {
			return fmt.Errorf("failed to get service: %w", err)
		}

		service.Meta.CertificateIssuedAt = time.Now()

		if err = transaction.UpdateService(ctx, service); err != nil {
			return fmt.Errorf("failed to update service certificate timestamp: %w", err)
		}

		return nil
	})
}

// SetStatus updates the status of the service (e.g., "active", "tunnel_not_created", etc.)
func (m *managerImpl) SetStatus(ctx context.Context, accountID, serviceID string, status reverseproxy.ProxyStatus) error {
	return m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		service, err := transaction.GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID)
		if err != nil {
			return fmt.Errorf("failed to get service: %w", err)
		}

		service.Meta.Status = string(status)

		if err = transaction.UpdateService(ctx, service); err != nil {
			return fmt.Errorf("failed to update service status: %w", err)
		}

		return nil
	})
}

func (m *managerImpl) ReloadService(ctx context.Context, accountID, serviceID string) error {
	service, err := m.store.GetServiceByID(ctx, store.LockingStrengthNone, accountID, serviceID)
	if err != nil {
		return fmt.Errorf("failed to get service: %w", err)
	}

	err = m.replaceHostByLookup(ctx, accountID, service)
	if err != nil {
		return fmt.Errorf("failed to replace host by lookup for service %s: %w", service.ID, err)
	}

	m.proxyGRPCServer.SendServiceUpdateToCluster(service.ToProtoMapping(reverseproxy.Update, "", m.proxyGRPCServer.GetOIDCValidationConfig()), service.ProxyCluster)

	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

func (m *managerImpl) ReloadAllServicesForAccount(ctx context.Context, accountID string) error {
	services, err := m.store.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("failed to get services: %w", err)
	}

	for _, service := range services {
		err = m.replaceHostByLookup(ctx, accountID, service)
		if err != nil {
			return fmt.Errorf("failed to replace host by lookup for service %s: %w", service.ID, err)
		}
		m.proxyGRPCServer.SendServiceUpdateToCluster(service.ToProtoMapping(reverseproxy.Update, "", m.proxyGRPCServer.GetOIDCValidationConfig()), service.ProxyCluster)
	}

	return nil
}

func (m *managerImpl) GetGlobalServices(ctx context.Context) ([]*reverseproxy.Service, error) {
	services, err := m.store.GetServices(ctx, store.LockingStrengthNone)
	if err != nil {
		return nil, fmt.Errorf("failed to get services: %w", err)
	}

	for _, service := range services {
		err = m.replaceHostByLookup(ctx, service.AccountID, service)
		if err != nil {
			return nil, fmt.Errorf("failed to replace host by lookup for service %s: %w", service.ID, err)
		}
	}

	return services, nil
}

func (m *managerImpl) GetServiceByID(ctx context.Context, accountID, serviceID string) (*reverseproxy.Service, error) {
	service, err := m.store.GetServiceByID(ctx, store.LockingStrengthNone, accountID, serviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get service: %w", err)
	}

	err = m.replaceHostByLookup(ctx, accountID, service)
	if err != nil {
		return nil, fmt.Errorf("failed to replace host by lookup for service %s: %w", service.ID, err)
	}

	return service, nil
}

func (m *managerImpl) GetAccountServices(ctx context.Context, accountID string) ([]*reverseproxy.Service, error) {
	services, err := m.store.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get services: %w", err)
	}

	for _, service := range services {
		err = m.replaceHostByLookup(ctx, accountID, service)
		if err != nil {
			return nil, fmt.Errorf("failed to replace host by lookup for service %s: %w", service.ID, err)
		}
	}

	return services, nil
}

func (m *managerImpl) GetServiceIDByTargetID(ctx context.Context, accountID string, resourceID string) (string, error) {
	target, err := m.store.GetServiceTargetByTargetID(ctx, store.LockingStrengthNone, accountID, resourceID)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Type() == status.NotFound {
			return "", nil
		}
		return "", fmt.Errorf("failed to get service target by resource ID: %w", err)
	}

	if target == nil {
		return "", nil
	}

	return target.ServiceID, nil
}
