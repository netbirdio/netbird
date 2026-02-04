package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ClusterDeriver derives the proxy cluster from a domain.
type ClusterDeriver interface {
	DeriveClusterFromDomain(ctx context.Context, domain string) (string, error)
}

type managerImpl struct {
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager
	proxyGRPCServer    *nbgrpc.ProxyServiceServer
	clusterDeriver     ClusterDeriver
}

// NewManager creates a new reverse proxy manager.
func NewManager(store store.Store, accountManager account.Manager, permissionsManager permissions.Manager, proxyGRPCServer *nbgrpc.ProxyServiceServer, clusterDeriver ClusterDeriver) reverseproxy.Manager {
	return &managerImpl{
		store:              store,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
		proxyGRPCServer:    proxyGRPCServer,
		clusterDeriver:     clusterDeriver,
	}
}

func (m *managerImpl) GetAllReverseProxies(ctx context.Context, accountID, userID string) ([]*reverseproxy.ReverseProxy, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetAccountReverseProxies(ctx, store.LockingStrengthNone, accountID)
}

func (m *managerImpl) GetReverseProxy(ctx context.Context, accountID, userID, reverseProxyID string) (*reverseproxy.ReverseProxy, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetReverseProxyByID(ctx, store.LockingStrengthNone, accountID, reverseProxyID)
}

func (m *managerImpl) CreateReverseProxy(ctx context.Context, accountID, userID string, reverseProxy *reverseproxy.ReverseProxy) (*reverseproxy.ReverseProxy, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	var proxyCluster string
	if m.clusterDeriver != nil {
		proxyCluster, err = m.clusterDeriver.DeriveClusterFromDomain(ctx, reverseProxy.Domain)
		if err != nil {
			log.WithError(err).Warnf("could not derive cluster from domain %s, updates will broadcast to all proxies", reverseProxy.Domain)
		}
	}

	authConfig := reverseProxy.Auth

	reverseProxy = reverseproxy.NewReverseProxy(accountID, reverseProxy.Name, reverseProxy.Domain, proxyCluster, reverseProxy.Targets, reverseProxy.Enabled)

	reverseProxy.Auth = authConfig

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		// Check for duplicate domain
		existingReverseProxy, err := transaction.GetReverseProxyByDomain(ctx, accountID, reverseProxy.Domain)
		if err != nil {
			if sErr, ok := status.FromError(err); !ok || sErr.Type() != status.NotFound {
				return fmt.Errorf("failed to check existing reverse proxy: %w", err)
			}
		}
		if existingReverseProxy != nil {
			return status.Errorf(status.AlreadyExists, "reverse proxy with domain %s already exists", reverseProxy.Domain)
		}

		if err = transaction.CreateReverseProxy(ctx, reverseProxy); err != nil {
			return fmt.Errorf("failed to create reverse proxy: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, reverseProxy.ID, accountID, activity.ReverseProxyCreated, reverseProxy.EventMeta())

	// TODO: refactor to avoid policy and group creation here
	group := &types.Group{
		ID:     xid.New().String(),
		Name:   reverseProxy.Name,
		Issued: types.GroupIssuedAPI,
	}
	err = m.accountManager.CreateGroup(ctx, accountID, activity.SystemInitiator, group)
	if err != nil {
		return nil, fmt.Errorf("failed to create default group for reverse proxy: %w", err)
	}

	for _, target := range reverseProxy.Targets {
		policyID := uuid.New().String()
		// TODO: support other resource types in the future
		targetType := types.ResourceTypePeer
		if target.TargetType == "resource" {
			targetType = types.ResourceTypeHost
		}
		policyRule := &types.PolicyRule{
			ID:                  policyID,
			PolicyID:            policyID,
			Name:                reverseProxy.Name,
			Enabled:             true,
			Action:              types.PolicyTrafficActionAccept,
			Protocol:            types.PolicyRuleProtocolALL,
			Sources:             []string{group.ID},
			DestinationResource: types.Resource{Type: targetType, ID: target.TargetId},
			Bidirectional:       false,
		}

		policy := &types.Policy{
			AccountID: accountID,
			Name:      reverseProxy.Name,
			Enabled:   true,
			Rules:     []*types.PolicyRule{policyRule},
		}
		_, err = m.accountManager.SavePolicy(ctx, accountID, activity.SystemInitiator, policy, true)
		if err != nil {
			return nil, fmt.Errorf("failed to create default policy for reverse proxy: %w", err)
		}
	}

	key, err := m.accountManager.CreateSetupKey(ctx, accountID, reverseProxy.Name, types.SetupKeyReusable, 0, []string{group.ID}, 0, activity.SystemInitiator, true, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create setup key for reverse proxy: %w", err)
	}

	m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Create, key.Key), reverseProxy.ProxyCluster)

	return reverseProxy, nil
}

func (m *managerImpl) UpdateReverseProxy(ctx context.Context, accountID, userID string, reverseProxy *reverseproxy.ReverseProxy) (*reverseproxy.ReverseProxy, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	var oldCluster string
	var domainChanged bool

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		existingReverseProxy, err := transaction.GetReverseProxyByID(ctx, store.LockingStrengthUpdate, accountID, reverseProxy.ID)
		if err != nil {
			return err
		}

		oldCluster = existingReverseProxy.ProxyCluster

		if existingReverseProxy.Domain != reverseProxy.Domain {
			domainChanged = true
			conflictReverseProxy, err := transaction.GetReverseProxyByDomain(ctx, accountID, reverseProxy.Domain)
			if err != nil {
				if sErr, ok := status.FromError(err); !ok || sErr.Type() != status.NotFound {
					return fmt.Errorf("check existing reverse proxy: %w", err)
				}
			}
			if conflictReverseProxy != nil && conflictReverseProxy.ID != reverseProxy.ID {
				return status.Errorf(status.AlreadyExists, "reverse proxy with domain %s already exists", reverseProxy.Domain)
			}

			if m.clusterDeriver != nil {
				newCluster, err := m.clusterDeriver.DeriveClusterFromDomain(ctx, reverseProxy.Domain)
				if err != nil {
					log.WithError(err).Warnf("could not derive cluster from domain %s", reverseProxy.Domain)
				}
				reverseProxy.ProxyCluster = newCluster
			}
		} else {
			reverseProxy.ProxyCluster = existingReverseProxy.ProxyCluster
		}

		reverseProxy.Meta = existingReverseProxy.Meta

		if err = transaction.UpdateReverseProxy(ctx, reverseProxy); err != nil {
			return fmt.Errorf("update reverse proxy: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, reverseProxy.ID, accountID, activity.ReverseProxyUpdated, reverseProxy.EventMeta())

	if domainChanged && oldCluster != reverseProxy.ProxyCluster {
		m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Delete, ""), oldCluster)
		m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Create, ""), reverseProxy.ProxyCluster)
	} else {
		m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Update, ""), reverseProxy.ProxyCluster)
	}

	return reverseProxy, nil
}

func (m *managerImpl) DeleteReverseProxy(ctx context.Context, accountID, userID, reverseProxyID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	var reverseProxy *reverseproxy.ReverseProxy
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		var err error
		reverseProxy, err = transaction.GetReverseProxyByID(ctx, store.LockingStrengthUpdate, accountID, reverseProxyID)
		if err != nil {
			return err
		}

		if err = transaction.DeleteReverseProxy(ctx, accountID, reverseProxyID); err != nil {
			return fmt.Errorf("failed to delete reverse proxy: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	m.accountManager.StoreEvent(ctx, userID, reverseProxyID, accountID, activity.ReverseProxyDeleted, reverseProxy.EventMeta())

	m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Delete, ""), reverseProxy.ProxyCluster)

	return nil
}

// SetCertificateIssuedAt sets the certificate issued timestamp to the current time.
// Call this when receiving a gRPC notification that the certificate was issued.
func (m *managerImpl) SetCertificateIssuedAt(ctx context.Context, accountID, reverseProxyID string) error {
	return m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		proxy, err := transaction.GetReverseProxyByID(ctx, store.LockingStrengthUpdate, accountID, reverseProxyID)
		if err != nil {
			return fmt.Errorf("failed to get reverse proxy: %w", err)
		}

		proxy.Meta.CertificateIssuedAt = time.Now()

		if err = transaction.UpdateReverseProxy(ctx, proxy); err != nil {
			return fmt.Errorf("failed to update reverse proxy certificate timestamp: %w", err)
		}

		return nil
	})
}

// SetStatus updates the status of the reverse proxy (e.g., "active", "tunnel_not_created", etc.)
func (m *managerImpl) SetStatus(ctx context.Context, accountID, reverseProxyID string, status reverseproxy.ProxyStatus) error {
	return m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		proxy, err := transaction.GetReverseProxyByID(ctx, store.LockingStrengthUpdate, accountID, reverseProxyID)
		if err != nil {
			return fmt.Errorf("failed to get reverse proxy: %w", err)
		}

		proxy.Meta.Status = string(status)

		if err = transaction.UpdateReverseProxy(ctx, proxy); err != nil {
			return fmt.Errorf("failed to update reverse proxy status: %w", err)
		}

		return nil
	})
}
