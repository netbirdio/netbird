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
	DeriveClusterFromDomain(ctx context.Context, domain string) (string, error)
}

type managerImpl struct {
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager
	proxyGRPCServer    *nbgrpc.ProxyServiceServer
	tokenStore         *nbgrpc.OneTimeTokenStore
	clusterDeriver     ClusterDeriver
}

// NewManager creates a new reverse proxy manager.
func NewManager(store store.Store, accountManager account.Manager, permissionsManager permissions.Manager, proxyGRPCServer *nbgrpc.ProxyServiceServer, tokenStore *nbgrpc.OneTimeTokenStore, clusterDeriver ClusterDeriver) reverseproxy.Manager {
	return &managerImpl{
		store:              store,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
		proxyGRPCServer:    proxyGRPCServer,
		tokenStore:         tokenStore,
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

	proxies, err := m.store.GetAccountReverseProxies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get reverse proxies: %w", err)
	}

	for _, proxy := range proxies {
		err = m.replaceHostByLookup(ctx, accountID, proxy)
		if err != nil {
			return nil, fmt.Errorf("failed to replace host by lookup for proxy %s: %w", proxy.ID, err)
		}
	}

	return proxies, nil
}

func (m *managerImpl) replaceHostByLookup(ctx context.Context, accountID string, proxy *reverseproxy.ReverseProxy) error {
	for _, target := range proxy.Targets {
		switch target.TargetType {
		case reverseproxy.TargetTypePeer:
			peer, err := m.store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, target.TargetId)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to get peer by id %s for reverse proxy %s: %v", target.TargetId, proxy.ID, err)
				target.Host = unknownHostPlaceholder
				continue
			}
			target.Host = peer.IP.String()
		case reverseproxy.TargetTypeHost:
			resource, err := m.store.GetNetworkResourceByID(ctx, store.LockingStrengthNone, accountID, target.TargetId)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to get resource by id %s for reverse proxy %s: %v", target.TargetId, proxy.ID, err)
				target.Host = unknownHostPlaceholder
				continue
			}
			target.Host = resource.Prefix.Addr().String()
		case reverseproxy.TargetTypeDomain:
			resource, err := m.store.GetNetworkResourceByID(ctx, store.LockingStrengthNone, accountID, target.TargetId)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to get resource by id %s for reverse proxy %s: %v", target.TargetId, proxy.ID, err)
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

func (m *managerImpl) GetReverseProxy(ctx context.Context, accountID, userID, reverseProxyID string) (*reverseproxy.ReverseProxy, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	proxy, err := m.store.GetReverseProxyByID(ctx, store.LockingStrengthNone, accountID, reverseProxyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get reverse proxy: %w", err)
	}

	err = m.replaceHostByLookup(ctx, accountID, proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to replace host by lookup for proxy %s: %w", proxy.ID, err)
	}
	return proxy, nil
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

	reverseProxy.AccountID = accountID
	reverseProxy.ProxyCluster = proxyCluster
	reverseProxy.InitNewRecord()

	// Generate session JWT signing keys
	keyPair, err := sessionkey.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate session keys: %w", err)
	}
	reverseProxy.SessionPrivateKey = keyPair.PrivateKey
	reverseProxy.SessionPublicKey = keyPair.PublicKey

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

		if err = validateTargetReferences(ctx, transaction, accountID, reverseProxy.Targets); err != nil {
			return err
		}

		if err = transaction.CreateReverseProxy(ctx, reverseProxy); err != nil {
			return fmt.Errorf("failed to create reverse proxy: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	token, err := m.tokenStore.GenerateToken(accountID, reverseProxy.ID, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authentication token: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, reverseProxy.ID, accountID, activity.ReverseProxyCreated, reverseProxy.EventMeta())

	err = m.replaceHostByLookup(ctx, accountID, reverseProxy)
	if err != nil {
		return nil, fmt.Errorf("failed to replace host by lookup for proxy %s: %w", reverseProxy.ID, err)
	}

	m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Create, token, m.proxyGRPCServer.GetOIDCValidationConfig()), reverseProxy.ProxyCluster)

	m.accountManager.UpdateAccountPeers(ctx, accountID)

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
	var reverseProxyEnabledChanged bool

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
		reverseProxy.SessionPrivateKey = existingReverseProxy.SessionPrivateKey
		reverseProxy.SessionPublicKey = existingReverseProxy.SessionPublicKey
		reverseProxyEnabledChanged = existingReverseProxy.Enabled != reverseProxy.Enabled

		if err = validateTargetReferences(ctx, transaction, accountID, reverseProxy.Targets); err != nil {
			return err
		}

		if err = transaction.UpdateReverseProxy(ctx, reverseProxy); err != nil {
			return fmt.Errorf("update reverse proxy: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, reverseProxy.ID, accountID, activity.ReverseProxyUpdated, reverseProxy.EventMeta())

	err = m.replaceHostByLookup(ctx, accountID, reverseProxy)
	if err != nil {
		return nil, fmt.Errorf("failed to replace host by lookup for proxy %s: %w", reverseProxy.ID, err)
	}

	token, err := m.tokenStore.GenerateToken(accountID, reverseProxy.ID, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authentication token: %w", err)
	}

	switch {
	case domainChanged && oldCluster != reverseProxy.ProxyCluster:
		m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Delete, "", m.proxyGRPCServer.GetOIDCValidationConfig()), oldCluster)
		m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Create, token, m.proxyGRPCServer.GetOIDCValidationConfig()), reverseProxy.ProxyCluster)
	case !reverseProxy.Enabled && reverseProxyEnabledChanged:
		m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Delete, "", m.proxyGRPCServer.GetOIDCValidationConfig()), reverseProxy.ProxyCluster)
	case reverseProxy.Enabled && reverseProxyEnabledChanged:
		m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Create, token, m.proxyGRPCServer.GetOIDCValidationConfig()), reverseProxy.ProxyCluster)
	default:
		m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Update, "", m.proxyGRPCServer.GetOIDCValidationConfig()), reverseProxy.ProxyCluster)

	}
	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return reverseProxy, nil
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

	m.proxyGRPCServer.SendReverseProxyUpdateToCluster(reverseProxy.ToProtoMapping(reverseproxy.Delete, "", m.proxyGRPCServer.GetOIDCValidationConfig()), reverseProxy.ProxyCluster)

	m.accountManager.UpdateAccountPeers(ctx, accountID)

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

func (m *managerImpl) ReloadReverseProxy(ctx context.Context, accountID, reverseProxyID string) error {
	proxy, err := m.store.GetReverseProxyByID(ctx, store.LockingStrengthNone, accountID, reverseProxyID)
	if err != nil {
		return fmt.Errorf("failed to get reverse proxy: %w", err)
	}

	err = m.replaceHostByLookup(ctx, accountID, proxy)
	if err != nil {
		return fmt.Errorf("failed to replace host by lookup for proxy %s: %w", proxy.ID, err)
	}

	m.proxyGRPCServer.SendReverseProxyUpdateToCluster(proxy.ToProtoMapping(reverseproxy.Update, "", m.proxyGRPCServer.GetOIDCValidationConfig()), proxy.ProxyCluster)

	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

func (m *managerImpl) ReloadAllReverseProxiesForAccount(ctx context.Context, accountID string) error {
	proxies, err := m.store.GetAccountReverseProxies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("failed to get reverse proxies: %w", err)
	}

	for _, proxy := range proxies {
		err = m.replaceHostByLookup(ctx, accountID, proxy)
		if err != nil {
			return fmt.Errorf("failed to replace host by lookup for proxy %s: %w", proxy.ID, err)
		}
		m.proxyGRPCServer.SendReverseProxyUpdateToCluster(proxy.ToProtoMapping(reverseproxy.Update, "", m.proxyGRPCServer.GetOIDCValidationConfig()), proxy.ProxyCluster)
	}

	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

func (m *managerImpl) GetGlobalReverseProxies(ctx context.Context) ([]*reverseproxy.ReverseProxy, error) {
	proxies, err := m.store.GetReverseProxies(ctx, store.LockingStrengthNone)
	if err != nil {
		return nil, fmt.Errorf("failed to get reverse proxies: %w", err)
	}

	for _, proxy := range proxies {
		err = m.replaceHostByLookup(ctx, proxy.AccountID, proxy)
		if err != nil {
			return nil, fmt.Errorf("failed to replace host by lookup for proxy %s: %w", proxy.ID, err)
		}
	}

	return proxies, nil
}

func (m *managerImpl) GetProxyByID(ctx context.Context, accountID, reverseProxyID string) (*reverseproxy.ReverseProxy, error) {
	proxy, err := m.store.GetReverseProxyByID(ctx, store.LockingStrengthNone, accountID, reverseProxyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get reverse proxy: %w", err)
	}

	err = m.replaceHostByLookup(ctx, accountID, proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to replace host by lookup for proxy %s: %w", proxy.ID, err)
	}

	return proxy, nil
}

func (m *managerImpl) GetAccountReverseProxies(ctx context.Context, accountID string) ([]*reverseproxy.ReverseProxy, error) {
	proxies, err := m.store.GetAccountReverseProxies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get reverse proxies: %w", err)
	}

	for _, proxy := range proxies {
		err = m.replaceHostByLookup(ctx, accountID, proxy)
		if err != nil {
			return nil, fmt.Errorf("failed to replace host by lookup for proxy %s: %w", proxy.ID, err)
		}
	}

	return proxies, nil
}

func (m *managerImpl) GetProxyIDByTargetID(ctx context.Context, accountID string, resourceID string) (string, error) {
	target, err := m.store.GetReverseProxyTargetByTargetID(ctx, store.LockingStrengthNone, accountID, resourceID)
	if err != nil {
		return "", fmt.Errorf("failed to get reverse proxy target by resource ID: %w", err)
	}

	if target == nil {
		return "", nil
	}

	return target.ReverseProxyID, nil
}
