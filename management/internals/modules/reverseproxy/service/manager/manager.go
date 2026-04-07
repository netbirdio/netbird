package manager

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"

	resourcetypes "github.com/netbirdio/netbird/management/server/networks/resources/types"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	defaultAutoAssignPortMin uint16 = 10000
	defaultAutoAssignPortMax uint16 = 49151

	// EnvAutoAssignPortMin overrides the lower bound for auto-assigned L4 listen ports.
	EnvAutoAssignPortMin = "NB_PROXY_PORT_MIN"
	// EnvAutoAssignPortMax overrides the upper bound for auto-assigned L4 listen ports.
	EnvAutoAssignPortMax = "NB_PROXY_PORT_MAX"
)

var (
	autoAssignPortMin = defaultAutoAssignPortMin
	autoAssignPortMax = defaultAutoAssignPortMax
)

func init() {
	autoAssignPortMin = portFromEnv(EnvAutoAssignPortMin, defaultAutoAssignPortMin)
	autoAssignPortMax = portFromEnv(EnvAutoAssignPortMax, defaultAutoAssignPortMax)
	if autoAssignPortMin > autoAssignPortMax {
		log.Warnf("port range invalid: %s (%d) > %s (%d), using defaults",
			EnvAutoAssignPortMin, autoAssignPortMin, EnvAutoAssignPortMax, autoAssignPortMax)
		autoAssignPortMin = defaultAutoAssignPortMin
		autoAssignPortMax = defaultAutoAssignPortMax
	}
}

func portFromEnv(key string, fallback uint16) uint16 {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	n, err := strconv.ParseUint(val, 10, 16)
	if err != nil {
		log.Warnf("invalid %s value %q, using default %d: %v", key, val, fallback, err)
		return fallback
	}
	return uint16(n)
}

const unknownHostPlaceholder = "unknown"

// ClusterDeriver derives the proxy cluster from a domain.
type ClusterDeriver interface {
	DeriveClusterFromDomain(ctx context.Context, accountID, domain string) (string, error)
	GetClusterDomains() []string
}

// CapabilityProvider queries proxy cluster capabilities from the database.
type CapabilityProvider interface {
	ClusterSupportsCustomPorts(ctx context.Context, clusterAddr string) *bool
	ClusterRequireSubdomain(ctx context.Context, clusterAddr string) *bool
}

type Manager struct {
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager
	proxyController    proxy.Controller
	capabilities       CapabilityProvider
	clusterDeriver     ClusterDeriver
	exposeReaper       *exposeReaper
}

// NewManager creates a new service manager.
func NewManager(store store.Store, accountManager account.Manager, permissionsManager permissions.Manager, proxyController proxy.Controller, capabilities CapabilityProvider, clusterDeriver ClusterDeriver) *Manager {
	mgr := &Manager{
		store:              store,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
		proxyController:    proxyController,
		capabilities:       capabilities,
		clusterDeriver:     clusterDeriver,
	}
	mgr.exposeReaper = &exposeReaper{manager: mgr}
	return mgr
}

// StartExposeReaper starts the background goroutine that reaps expired ephemeral services.
func (m *Manager) StartExposeReaper(ctx context.Context) {
	m.exposeReaper.StartExposeReaper(ctx)
}

// GetActiveClusters returns all active proxy clusters with their connected proxy count.
func (m *Manager) GetActiveClusters(ctx context.Context, accountID, userID string) ([]proxy.Cluster, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetActiveProxyClusters(ctx)
}

func (m *Manager) GetAllServices(ctx context.Context, accountID, userID string) ([]*service.Service, error) {
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

func (m *Manager) replaceHostByLookup(ctx context.Context, accountID string, s *service.Service) error {
	for _, target := range s.Targets {
		switch target.TargetType {
		case service.TargetTypePeer:
			peer, err := m.store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, target.TargetId)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to get peer by id %s for service %s: %v", target.TargetId, s.ID, err)
				target.Host = unknownHostPlaceholder
				continue
			}
			target.Host = peer.IP.String()
		case service.TargetTypeHost:
			resource, err := m.store.GetNetworkResourceByID(ctx, store.LockingStrengthNone, accountID, target.TargetId)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to get resource by id %s for service %s: %v", target.TargetId, s.ID, err)
				target.Host = unknownHostPlaceholder
				continue
			}
			target.Host = resource.Prefix.Addr().String()
		case service.TargetTypeDomain:
			resource, err := m.store.GetNetworkResourceByID(ctx, store.LockingStrengthNone, accountID, target.TargetId)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to get resource by id %s for service %s: %v", target.TargetId, s.ID, err)
				target.Host = unknownHostPlaceholder
				continue
			}
			target.Host = resource.Domain
		case service.TargetTypeSubnet:
			// For subnets we do not do any lookups on the resource
		default:
			return fmt.Errorf("unknown target type: %s", target.TargetType)
		}
	}

	return nil
}

func (m *Manager) GetService(ctx context.Context, accountID, userID, serviceID string) (*service.Service, error) {
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

func (m *Manager) CreateService(ctx context.Context, accountID, userID string, s *service.Service) (*service.Service, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err := m.initializeServiceForCreate(ctx, accountID, s); err != nil {
		return nil, err
	}

	if err := m.persistNewService(ctx, accountID, s); err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, s.ID, accountID, activity.ServiceCreated, s.EventMeta())

	err = m.replaceHostByLookup(ctx, accountID, s)
	if err != nil {
		return nil, fmt.Errorf("failed to replace host by lookup for service %s: %w", s.ID, err)
	}

	m.proxyController.SendServiceUpdateToCluster(ctx, accountID, s.ToProtoMapping(service.Create, "", m.proxyController.GetOIDCValidationConfig()), s.ProxyCluster)

	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return s, nil
}

func (m *Manager) initializeServiceForCreate(ctx context.Context, accountID string, service *service.Service) error {
	if m.clusterDeriver != nil {
		proxyCluster, err := m.clusterDeriver.DeriveClusterFromDomain(ctx, accountID, service.Domain)
		if err != nil {
			log.WithError(err).Warnf("could not derive cluster from domain %s, updates will broadcast to all proxy servers", service.Domain)
			return status.Errorf(status.PreconditionFailed, "could not derive cluster from domain %s: %v", service.Domain, err)
		}
		service.ProxyCluster = proxyCluster

		if err := m.validateSubdomainRequirement(ctx, service.Domain, proxyCluster); err != nil {
			return err
		}
	}

	service.AccountID = accountID
	service.InitNewRecord()

	if err := service.Auth.HashSecrets(); err != nil {
		return fmt.Errorf("hash secrets: %w", err)
	}

	for i, h := range service.Auth.HeaderAuths {
		if h != nil && h.Enabled && h.Value == "" {
			return status.Errorf(status.InvalidArgument, "header_auths[%d]: value is required", i)
		}
	}

	keyPair, err := sessionkey.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate session keys: %w", err)
	}
	service.SessionPrivateKey = keyPair.PrivateKey
	service.SessionPublicKey = keyPair.PublicKey

	return nil
}

// validateSubdomainRequirement checks whether the domain can be used bare
// (without a subdomain label) on the given cluster. If the cluster reports
// require_subdomain=true and the domain equals the cluster domain, it rejects.
func (m *Manager) validateSubdomainRequirement(ctx context.Context, domain, cluster string) error {
	if domain != cluster {
		return nil
	}
	requireSub := m.capabilities.ClusterRequireSubdomain(ctx, cluster)
	if requireSub != nil && *requireSub {
		return status.Errorf(status.InvalidArgument, "domain %s requires a subdomain label", domain)
	}
	return nil
}

func (m *Manager) persistNewService(ctx context.Context, accountID string, svc *service.Service) error {
	customPorts := m.clusterCustomPorts(ctx, svc)

	return m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if svc.Domain != "" {
			if err := m.checkDomainAvailable(ctx, transaction, svc.Domain, ""); err != nil {
				return err
			}
		}

		if err := m.ensureL4Port(ctx, transaction, svc, customPorts); err != nil {
			return err
		}

		if err := m.checkPortConflict(ctx, transaction, svc); err != nil {
			return err
		}

		if err := validateTargetReferences(ctx, transaction, accountID, svc.Targets); err != nil {
			return err
		}

		if err := transaction.CreateService(ctx, svc); err != nil {
			return fmt.Errorf("create service: %w", err)
		}

		return nil
	})
}

// clusterCustomPorts queries whether the cluster supports custom ports.
// Must be called before entering a transaction: the underlying query uses
// the main DB handle, which deadlocks when called inside a transaction
// that already holds the connection.
func (m *Manager) clusterCustomPorts(ctx context.Context, svc *service.Service) *bool {
	if !service.IsL4Protocol(svc.Mode) {
		return nil
	}
	return m.capabilities.ClusterSupportsCustomPorts(ctx, svc.ProxyCluster)
}

// ensureL4Port auto-assigns a listen port when needed and validates cluster support.
// customPorts must be pre-computed via clusterCustomPorts before entering a transaction.
func (m *Manager) ensureL4Port(ctx context.Context, tx store.Store, svc *service.Service, customPorts *bool) error {
	if !service.IsL4Protocol(svc.Mode) {
		return nil
	}
	if service.IsPortBasedProtocol(svc.Mode) && svc.ListenPort > 0 && (customPorts == nil || !*customPorts) {
		if svc.Source != service.SourceEphemeral {
			return status.Errorf(status.InvalidArgument, "custom ports not supported on cluster %s", svc.ProxyCluster)
		}
		svc.ListenPort = 0
	}
	if svc.ListenPort == 0 {
		port, err := m.assignPort(ctx, tx, svc.ProxyCluster)
		if err != nil {
			return err
		}
		svc.ListenPort = port
		svc.PortAutoAssigned = true
	}
	return nil
}

// checkPortConflict rejects L4 services that would conflict on the same listener.
// For TCP/UDP: unique per cluster+protocol+port.
// For TLS: unique per cluster+port+domain (SNI routing allows sharing ports).
// Cross-protocol conflicts (TLS vs raw TCP) are intentionally not checked:
// the proxy router multiplexes TLS (via SNI) and raw TCP (via fallback) on the same listener.
func (m *Manager) checkPortConflict(ctx context.Context, transaction store.Store, svc *service.Service) error {
	if !service.IsL4Protocol(svc.Mode) || svc.ListenPort == 0 {
		return nil
	}

	existing, err := transaction.GetServicesByClusterAndPort(ctx, store.LockingStrengthUpdate, svc.ProxyCluster, svc.Mode, svc.ListenPort)
	if err != nil {
		return fmt.Errorf("query port conflicts: %w", err)
	}
	for _, s := range existing {
		if s.ID == svc.ID {
			continue
		}
		// TLS services on the same port are allowed if they have different domains (SNI routing)
		if svc.Mode == service.ModeTLS && s.Domain != svc.Domain {
			continue
		}
		return status.Errorf(status.AlreadyExists,
			"%s port %d is already in use by service %q on cluster %s",
			svc.Mode, svc.ListenPort, s.Name, svc.ProxyCluster)
	}

	return nil
}

// assignPort picks a random available port on the cluster within the auto-assign range.
func (m *Manager) assignPort(ctx context.Context, tx store.Store, cluster string) (uint16, error) {
	services, err := tx.GetServicesByCluster(ctx, store.LockingStrengthUpdate, cluster)
	if err != nil {
		return 0, fmt.Errorf("query cluster ports: %w", err)
	}

	occupied := make(map[uint16]struct{}, len(services))
	for _, s := range services {
		if s.ListenPort > 0 {
			occupied[s.ListenPort] = struct{}{}
		}
	}

	portRange := int(autoAssignPortMax-autoAssignPortMin) + 1
	for range 100 {
		port := autoAssignPortMin + uint16(rand.IntN(portRange))
		if _, taken := occupied[port]; !taken {
			return port, nil
		}
	}

	for port := autoAssignPortMin; port <= autoAssignPortMax; port++ {
		if _, taken := occupied[port]; !taken {
			return port, nil
		}
	}

	return 0, status.Errorf(status.PreconditionFailed, "no available ports on cluster %s", cluster)
}

// persistNewEphemeralService creates an ephemeral service inside a single transaction
// that also enforces the duplicate and per-peer limit checks atomically.
// The count and exists queries use FOR UPDATE locking to serialize concurrent creates
// for the same peer, preventing the per-peer limit from being bypassed.
func (m *Manager) persistNewEphemeralService(ctx context.Context, accountID, peerID string, svc *service.Service) error {
	customPorts := m.clusterCustomPorts(ctx, svc)

	return m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err := m.validateEphemeralPreconditions(ctx, transaction, accountID, peerID, svc); err != nil {
			return err
		}

		if err := m.ensureL4Port(ctx, transaction, svc, customPorts); err != nil {
			return err
		}

		if err := m.checkPortConflict(ctx, transaction, svc); err != nil {
			return err
		}

		if err := validateTargetReferences(ctx, transaction, accountID, svc.Targets); err != nil {
			return err
		}

		if err := transaction.CreateService(ctx, svc); err != nil {
			return fmt.Errorf("create service: %w", err)
		}

		return nil
	})
}

func (m *Manager) validateEphemeralPreconditions(ctx context.Context, transaction store.Store, accountID, peerID string, svc *service.Service) error {
	// Lock the peer row to serialize concurrent creates for the same peer.
	if _, err := transaction.GetPeerByID(ctx, store.LockingStrengthUpdate, accountID, peerID); err != nil {
		return fmt.Errorf("lock peer row: %w", err)
	}

	exists, err := transaction.EphemeralServiceExists(ctx, store.LockingStrengthUpdate, accountID, peerID, svc.Domain)
	if err != nil {
		return fmt.Errorf("check existing expose: %w", err)
	}
	if exists {
		return status.Errorf(status.AlreadyExists, "peer already has an active expose session for this domain")
	}

	if err := m.checkDomainAvailable(ctx, transaction, svc.Domain, ""); err != nil {
		return err
	}

	count, err := transaction.CountEphemeralServicesByPeer(ctx, store.LockingStrengthUpdate, accountID, peerID)
	if err != nil {
		return fmt.Errorf("count peer exposes: %w", err)
	}
	if count >= int64(maxExposesPerPeer) {
		return status.Errorf(status.PreconditionFailed, "peer has reached the maximum number of active expose sessions (%d)", maxExposesPerPeer)
	}

	return nil
}

// checkDomainAvailable checks that no other service already uses this domain.
func (m *Manager) checkDomainAvailable(ctx context.Context, transaction store.Store, domain, excludeServiceID string) error {
	existingService, err := transaction.GetServiceByDomain(ctx, domain)
	if err != nil {
		if sErr, ok := status.FromError(err); !ok || sErr.Type() != status.NotFound {
			return fmt.Errorf("check existing service: %w", err)
		}
		return nil
	}

	if existingService != nil && existingService.ID != excludeServiceID {
		return status.Errorf(status.AlreadyExists, "domain already taken")
	}

	return nil
}

func (m *Manager) UpdateService(ctx context.Context, accountID, userID string, service *service.Service) (*service.Service, error) {
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

	m.sendServiceUpdateNotifications(ctx, accountID, service, updateInfo)
	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return service, nil
}

type serviceUpdateInfo struct {
	oldCluster            string
	domainChanged         bool
	serviceEnabledChanged bool
}

func (m *Manager) persistServiceUpdate(ctx context.Context, accountID string, service *service.Service) (*serviceUpdateInfo, error) {
	effectiveCluster, err := m.resolveEffectiveCluster(ctx, accountID, service)
	if err != nil {
		return nil, err
	}

	svcForCaps := *service
	svcForCaps.ProxyCluster = effectiveCluster
	customPorts := m.clusterCustomPorts(ctx, &svcForCaps)

	var updateInfo serviceUpdateInfo

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		return m.executeServiceUpdate(ctx, transaction, accountID, service, &updateInfo, customPorts)
	})

	return &updateInfo, err
}

// resolveEffectiveCluster determines the cluster that will be used after the update.
// It reads the existing service without locking and derives the new cluster if the domain changed.
func (m *Manager) resolveEffectiveCluster(ctx context.Context, accountID string, svc *service.Service) (string, error) {
	existing, err := m.store.GetServiceByID(ctx, store.LockingStrengthNone, accountID, svc.ID)
	if err != nil {
		return "", err
	}

	if existing.Domain == svc.Domain {
		return existing.ProxyCluster, nil
	}

	if m.clusterDeriver != nil {
		derived, err := m.clusterDeriver.DeriveClusterFromDomain(ctx, accountID, svc.Domain)
		if err != nil {
			log.WithError(err).Warnf("could not derive cluster from domain %s", svc.Domain)
		} else {
			return derived, nil
		}
	}

	return existing.ProxyCluster, nil
}

func (m *Manager) executeServiceUpdate(ctx context.Context, transaction store.Store, accountID string, service *service.Service, updateInfo *serviceUpdateInfo, customPorts *bool) error {
	existingService, err := transaction.GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, service.ID)
	if err != nil {
		return err
	}

	if existingService.Terminated {
		return status.Errorf(status.PermissionDenied, "service is terminated and cannot be updated")
	}

	if err := validateProtocolChange(existingService.Mode, service.Mode); err != nil {
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

	if err := m.validateSubdomainRequirement(ctx, service.Domain, service.ProxyCluster); err != nil {
		return err
	}

	m.preserveExistingAuthSecrets(service, existingService)
	if err := validateHeaderAuthValues(service.Auth.HeaderAuths); err != nil {
		return err
	}
	m.preserveServiceMetadata(service, existingService)
	m.preserveListenPort(service, existingService)
	updateInfo.serviceEnabledChanged = existingService.Enabled != service.Enabled

	if err := m.ensureL4Port(ctx, transaction, service, customPorts); err != nil {
		return err
	}
	if err := m.checkPortConflict(ctx, transaction, service); err != nil {
		return err
	}
	if err := validateTargetReferences(ctx, transaction, accountID, service.Targets); err != nil {
		return err
	}
	if err := transaction.UpdateService(ctx, service); err != nil {
		return fmt.Errorf("update service: %w", err)
	}

	return nil
}

func (m *Manager) handleDomainChange(ctx context.Context, transaction store.Store, accountID string, svc *service.Service) error {
	if err := m.checkDomainAvailable(ctx, transaction, svc.Domain, svc.ID); err != nil {
		return err
	}

	if m.clusterDeriver != nil {
		newCluster, err := m.clusterDeriver.DeriveClusterFromDomain(ctx, accountID, svc.Domain)
		if err != nil {
			log.WithError(err).Warnf("could not derive cluster from domain %s", svc.Domain)
		} else {
			svc.ProxyCluster = newCluster
		}
	}

	return nil
}

// validateProtocolChange rejects mode changes on update.
// Only empty<->HTTP is allowed; all other transitions are rejected.
func validateProtocolChange(oldMode, newMode string) error {
	if newMode == "" || newMode == oldMode {
		return nil
	}
	if isHTTPFamily(oldMode) && isHTTPFamily(newMode) {
		return nil
	}
	return status.Errorf(status.InvalidArgument, "cannot change mode from %q to %q", oldMode, newMode)
}

func isHTTPFamily(mode string) bool {
	return mode == "" || mode == "http"
}

func (m *Manager) preserveExistingAuthSecrets(svc, existingService *service.Service) {
	if svc.Auth.PasswordAuth != nil && svc.Auth.PasswordAuth.Enabled &&
		existingService.Auth.PasswordAuth != nil && existingService.Auth.PasswordAuth.Enabled &&
		svc.Auth.PasswordAuth.Password == "" {
		svc.Auth.PasswordAuth = existingService.Auth.PasswordAuth
	}

	if svc.Auth.PinAuth != nil && svc.Auth.PinAuth.Enabled &&
		existingService.Auth.PinAuth != nil && existingService.Auth.PinAuth.Enabled &&
		svc.Auth.PinAuth.Pin == "" {
		svc.Auth.PinAuth = existingService.Auth.PinAuth
	}

	preserveHeaderAuthHashes(svc.Auth.HeaderAuths, existingService.Auth.HeaderAuths)
}

// preserveHeaderAuthHashes fills in empty header auth values from the existing
// service so that unchanged secrets are not lost on update.
func preserveHeaderAuthHashes(headers, existing []*service.HeaderAuthConfig) {
	if len(headers) == 0 || len(existing) == 0 {
		return
	}
	existingByHeader := make(map[string]string, len(existing))
	for _, h := range existing {
		if h != nil && h.Value != "" {
			existingByHeader[http.CanonicalHeaderKey(h.Header)] = h.Value
		}
	}
	for _, h := range headers {
		if h != nil && h.Enabled && h.Value == "" {
			if hash, ok := existingByHeader[http.CanonicalHeaderKey(h.Header)]; ok {
				h.Value = hash
			}
		}
	}
}

// validateHeaderAuthValues checks that all enabled header auths have a value
// (either freshly provided or preserved from the existing service).
func validateHeaderAuthValues(headers []*service.HeaderAuthConfig) error {
	for i, h := range headers {
		if h != nil && h.Enabled && h.Value == "" {
			return status.Errorf(status.InvalidArgument, "header_auths[%d]: value is required", i)
		}
	}
	return nil
}

func (m *Manager) preserveServiceMetadata(service, existingService *service.Service) {
	service.Meta = existingService.Meta
	service.SessionPrivateKey = existingService.SessionPrivateKey
	service.SessionPublicKey = existingService.SessionPublicKey
}

func (m *Manager) preserveListenPort(svc, existing *service.Service) {
	if existing.ListenPort > 0 && svc.ListenPort == 0 {
		svc.ListenPort = existing.ListenPort
		svc.PortAutoAssigned = existing.PortAutoAssigned
	}
}

func (m *Manager) sendServiceUpdateNotifications(ctx context.Context, accountID string, s *service.Service, updateInfo *serviceUpdateInfo) {
	oidcCfg := m.proxyController.GetOIDCValidationConfig()

	switch {
	case updateInfo.domainChanged || updateInfo.oldCluster != s.ProxyCluster:
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, s.ToProtoMapping(service.Delete, "", oidcCfg), updateInfo.oldCluster)
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, s.ToProtoMapping(service.Create, "", oidcCfg), s.ProxyCluster)
	case !s.Enabled && updateInfo.serviceEnabledChanged:
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, s.ToProtoMapping(service.Delete, "", oidcCfg), s.ProxyCluster)
	case s.Enabled && updateInfo.serviceEnabledChanged:
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, s.ToProtoMapping(service.Create, "", oidcCfg), s.ProxyCluster)
	default:
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, s.ToProtoMapping(service.Update, "", oidcCfg), s.ProxyCluster)
	}
}

// validateTargetReferences checks that all target IDs reference existing peers or resources in the account.
func validateTargetReferences(ctx context.Context, transaction store.Store, accountID string, targets []*service.Target) error {
	for _, target := range targets {
		switch target.TargetType {
		case service.TargetTypePeer:
			if err := validatePeerTarget(ctx, transaction, accountID, target); err != nil {
				return err
			}
		case service.TargetTypeHost, service.TargetTypeSubnet, service.TargetTypeDomain:
			if err := validateResourceTarget(ctx, transaction, accountID, target); err != nil {
				return err
			}
		default:
			return status.Errorf(status.InvalidArgument, "unknown target type %q for target %q", target.TargetType, target.TargetId)
		}
	}
	return nil
}

func validatePeerTarget(ctx context.Context, transaction store.Store, accountID string, target *service.Target) error {
	if _, err := transaction.GetPeerByID(ctx, store.LockingStrengthShare, accountID, target.TargetId); err != nil {
		if sErr, ok := status.FromError(err); ok && sErr.Type() == status.NotFound {
			return status.Errorf(status.InvalidArgument, "peer target %q not found in account", target.TargetId)
		}
		return fmt.Errorf("look up peer target %q: %w", target.TargetId, err)
	}
	return nil
}

func validateResourceTarget(ctx context.Context, transaction store.Store, accountID string, target *service.Target) error {
	resource, err := transaction.GetNetworkResourceByID(ctx, store.LockingStrengthShare, accountID, target.TargetId)
	if err != nil {
		if sErr, ok := status.FromError(err); ok && sErr.Type() == status.NotFound {
			return status.Errorf(status.InvalidArgument, "resource target %q not found in account", target.TargetId)
		}
		return fmt.Errorf("look up resource target %q: %w", target.TargetId, err)
	}
	return validateResourceTargetType(target, resource)
}

// validateResourceTargetType checks that target_type matches the actual network resource type.
func validateResourceTargetType(target *service.Target, resource *resourcetypes.NetworkResource) error {
	expected := resourcetypes.NetworkResourceType(target.TargetType)
	if resource.Type != expected {
		return status.Errorf(status.InvalidArgument,
			"target %q has target_type %q but resource is of type %q",
			target.TargetId, target.TargetType, resource.Type,
		)
	}
	return nil
}

func (m *Manager) DeleteService(ctx context.Context, accountID, userID, serviceID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	var s *service.Service
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		var err error
		s, err = transaction.GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID)
		if err != nil {
			return err
		}

		if err = transaction.DeleteServiceTargets(ctx, accountID, serviceID); err != nil {
			return fmt.Errorf("failed to delete targets: %w", err)
		}

		if err = transaction.DeleteService(ctx, accountID, serviceID); err != nil {
			return fmt.Errorf("failed to delete service: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	m.accountManager.StoreEvent(ctx, userID, serviceID, accountID, activity.ServiceDeleted, s.EventMeta())

	m.proxyController.SendServiceUpdateToCluster(ctx, accountID, s.ToProtoMapping(service.Delete, "", m.proxyController.GetOIDCValidationConfig()), s.ProxyCluster)

	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

func (m *Manager) DeleteAllServices(ctx context.Context, accountID, userID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	var services []*service.Service
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		var err error
		services, err = transaction.GetAccountServices(ctx, store.LockingStrengthUpdate, accountID)
		if err != nil {
			return err
		}

		for _, svc := range services {
			if err = transaction.DeleteService(ctx, accountID, svc.ID); err != nil {
				return fmt.Errorf("failed to delete service: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	oidcCfg := m.proxyController.GetOIDCValidationConfig()

	for _, svc := range services {
		m.accountManager.StoreEvent(ctx, userID, svc.ID, accountID, activity.ServiceDeleted, svc.EventMeta())
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, svc.ToProtoMapping(service.Delete, "", oidcCfg), svc.ProxyCluster)
	}

	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

// SetCertificateIssuedAt sets the certificate issued timestamp to the current time.
// Call this when receiving a gRPC notification that the certificate was issued.
func (m *Manager) SetCertificateIssuedAt(ctx context.Context, accountID, serviceID string) error {
	return m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		service, err := transaction.GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID)
		if err != nil {
			return fmt.Errorf("failed to get service: %w", err)
		}

		now := time.Now()
		service.Meta.CertificateIssuedAt = &now

		if err = transaction.UpdateService(ctx, service); err != nil {
			return fmt.Errorf("failed to update service certificate timestamp: %w", err)
		}

		return nil
	})
}

// SetStatus updates the status of the service (e.g., "active", "tunnel_not_created", etc.)
func (m *Manager) SetStatus(ctx context.Context, accountID, serviceID string, status service.Status) error {
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

func (m *Manager) ReloadService(ctx context.Context, accountID, serviceID string) error {
	s, err := m.store.GetServiceByID(ctx, store.LockingStrengthNone, accountID, serviceID)
	if err != nil {
		return fmt.Errorf("failed to get service: %w", err)
	}

	err = m.replaceHostByLookup(ctx, accountID, s)
	if err != nil {
		return fmt.Errorf("failed to replace host by lookup for service %s: %w", s.ID, err)
	}

	m.proxyController.SendServiceUpdateToCluster(ctx, accountID, s.ToProtoMapping(service.Update, "", m.proxyController.GetOIDCValidationConfig()), s.ProxyCluster)

	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

func (m *Manager) ReloadAllServicesForAccount(ctx context.Context, accountID string) error {
	services, err := m.store.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("failed to get services: %w", err)
	}

	for _, s := range services {
		err = m.replaceHostByLookup(ctx, accountID, s)
		if err != nil {
			return fmt.Errorf("failed to replace host by lookup for service %s: %w", s.ID, err)
		}
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, s.ToProtoMapping(service.Update, "", m.proxyController.GetOIDCValidationConfig()), s.ProxyCluster)
	}

	return nil
}

func (m *Manager) GetGlobalServices(ctx context.Context) ([]*service.Service, error) {
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

func (m *Manager) GetServiceByID(ctx context.Context, accountID, serviceID string) (*service.Service, error) {
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

func (m *Manager) GetAccountServices(ctx context.Context, accountID string) ([]*service.Service, error) {
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

func (m *Manager) GetServiceIDByTargetID(ctx context.Context, accountID string, resourceID string) (string, error) {
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

// validateExposePermission checks whether the peer is allowed to use the expose feature.
// It verifies the account has peer expose enabled and that the peer belongs to an allowed group.
func (m *Manager) validateExposePermission(ctx context.Context, accountID, peerID string) error {
	settings, err := m.store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account settings: %v", err)
		return status.Errorf(status.Internal, "get account settings: %v", err)
	}

	if !settings.PeerExposeEnabled {
		return status.Errorf(status.PermissionDenied, "peer expose is not enabled for this account")
	}

	if len(settings.PeerExposeGroups) == 0 {
		return status.Errorf(status.PermissionDenied, "no group is set for peer expose")
	}

	peerGroupIDs, err := m.store.GetPeerGroupIDs(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get peer group IDs: %v", err)
		return status.Errorf(status.Internal, "get peer groups: %v", err)
	}

	for _, pg := range peerGroupIDs {
		if slices.Contains(settings.PeerExposeGroups, pg) {
			return nil
		}
	}

	return status.Errorf(status.PermissionDenied, "peer is not in an allowed expose group")
}

func (m *Manager) resolveDefaultDomain(serviceName string) (string, error) {
	return m.buildRandomDomain(serviceName)
}

// CreateServiceFromPeer creates a service initiated by a peer expose request.
// It validates the request, checks expose permissions, enforces the per-peer limit,
// creates the service, and tracks it for TTL-based reaping.
func (m *Manager) CreateServiceFromPeer(ctx context.Context, accountID, peerID string, req *service.ExposeServiceRequest) (*service.ExposeServiceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(status.InvalidArgument, "validate expose request: %v", err)
	}

	if err := m.validateExposePermission(ctx, accountID, peerID); err != nil {
		return nil, err
	}

	serviceName, err := service.GenerateExposeName(req.NamePrefix)
	if err != nil {
		return nil, status.Errorf(status.InvalidArgument, "generate service name: %v", err)
	}

	svc := req.ToService(accountID, peerID, serviceName)
	svc.Source = service.SourceEphemeral

	if svc.Domain == "" {
		domain, err := m.resolveDefaultDomain(svc.Name)
		if err != nil {
			return nil, err
		}
		svc.Domain = domain
	}

	if svc.Auth.BearerAuth != nil && svc.Auth.BearerAuth.Enabled {
		groupIDs, err := m.getGroupIDsFromNames(ctx, accountID, svc.Auth.BearerAuth.DistributionGroups)
		if err != nil {
			return nil, fmt.Errorf("get group ids for service %s: %w", svc.Name, err)
		}
		svc.Auth.BearerAuth.DistributionGroups = groupIDs
	}

	if err := m.initializeServiceForCreate(ctx, accountID, svc); err != nil {
		return nil, err
	}

	peer, err := m.store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		return nil, err
	}

	svc.SourcePeer = peerID

	now := time.Now()
	svc.Meta.LastRenewedAt = &now

	if err := m.persistNewEphemeralService(ctx, accountID, peerID, svc); err != nil {
		return nil, err
	}

	meta := addPeerInfoToEventMeta(svc.EventMeta(), peer)
	m.accountManager.StoreEvent(ctx, peerID, svc.ID, accountID, activity.PeerServiceExposed, meta)

	if err := m.replaceHostByLookup(ctx, accountID, svc); err != nil {
		return nil, fmt.Errorf("replace host by lookup for service %s: %w", svc.ID, err)
	}

	m.proxyController.SendServiceUpdateToCluster(ctx, accountID, svc.ToProtoMapping(service.Create, "", m.proxyController.GetOIDCValidationConfig()), svc.ProxyCluster)
	m.accountManager.UpdateAccountPeers(ctx, accountID)

	serviceURL := "https://" + svc.Domain
	if service.IsL4Protocol(svc.Mode) {
		serviceURL = fmt.Sprintf("%s://%s:%d", svc.Mode, svc.Domain, svc.ListenPort)
	}

	return &service.ExposeServiceResponse{
		ServiceName:      svc.Name,
		ServiceURL:       serviceURL,
		Domain:           svc.Domain,
		PortAutoAssigned: svc.PortAutoAssigned,
	}, nil
}

func (m *Manager) getGroupIDsFromNames(ctx context.Context, accountID string, groupNames []string) ([]string, error) {
	if len(groupNames) == 0 {
		return []string{}, fmt.Errorf("no group names provided")
	}
	groupIDs := make([]string, 0, len(groupNames))
	for _, groupName := range groupNames {
		g, err := m.accountManager.GetGroupByName(ctx, groupName, accountID)
		if err != nil {
			return nil, fmt.Errorf("failed to get group by name %s: %w", groupName, err)
		}
		groupIDs = append(groupIDs, g.ID)
	}
	return groupIDs, nil
}

func (m *Manager) getDefaultClusterDomain() (string, error) {
	if m.clusterDeriver == nil {
		return "", fmt.Errorf("unable to get cluster domain")
	}
	clusterDomains := m.clusterDeriver.GetClusterDomains()
	if len(clusterDomains) == 0 {
		return "", fmt.Errorf("no cluster domains available")
	}
	return clusterDomains[rand.IntN(len(clusterDomains))], nil
}

func (m *Manager) buildRandomDomain(name string) (string, error) {
	domain, err := m.getDefaultClusterDomain()
	if err != nil {
		return "", err
	}
	return name + "." + domain, nil
}

// RenewServiceFromPeer updates the DB timestamp for the peer's ephemeral service.
func (m *Manager) RenewServiceFromPeer(ctx context.Context, accountID, peerID, serviceID string) error {
	return m.store.RenewEphemeralService(ctx, accountID, peerID, serviceID)
}

// StopServiceFromPeer stops a peer's active expose session by deleting the service from the DB.
func (m *Manager) StopServiceFromPeer(ctx context.Context, accountID, peerID, serviceID string) error {
	if err := m.deleteServiceFromPeer(ctx, accountID, peerID, serviceID, false); err != nil {
		log.WithContext(ctx).Errorf("failed to delete peer-exposed service %s: %v", serviceID, err)
		return err
	}
	return nil
}

// deleteServiceFromPeer deletes a peer-initiated service identified by service ID.
// When expired is true, the activity is recorded as PeerServiceExposeExpired instead of PeerServiceUnexposed.
func (m *Manager) deleteServiceFromPeer(ctx context.Context, accountID, peerID, serviceID string, expired bool) error {
	activityCode := activity.PeerServiceUnexposed
	if expired {
		activityCode = activity.PeerServiceExposeExpired
	}
	return m.deletePeerService(ctx, accountID, peerID, serviceID, activityCode)
}

func (m *Manager) deletePeerService(ctx context.Context, accountID, peerID, serviceID string, activityCode activity.Activity) error {
	var svc *service.Service
	err := m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		var err error
		svc, err = transaction.GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID)
		if err != nil {
			return err
		}

		if svc.Source != service.SourceEphemeral {
			return status.Errorf(status.PermissionDenied, "cannot delete API-created service via peer expose")
		}

		if svc.SourcePeer != peerID {
			return status.Errorf(status.PermissionDenied, "cannot delete service exposed by another peer")
		}

		if err = transaction.DeleteService(ctx, accountID, serviceID); err != nil {
			return fmt.Errorf("delete service: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	peer, err := m.store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		log.WithContext(ctx).Debugf("failed to get peer %s for event metadata: %v", peerID, err)
		peer = nil
	}

	meta := addPeerInfoToEventMeta(svc.EventMeta(), peer)

	m.accountManager.StoreEvent(ctx, peerID, serviceID, accountID, activityCode, meta)

	m.proxyController.SendServiceUpdateToCluster(ctx, accountID, svc.ToProtoMapping(service.Delete, "", m.proxyController.GetOIDCValidationConfig()), svc.ProxyCluster)

	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

// deleteExpiredPeerService deletes an ephemeral service by ID after re-checking
// that it is still expired under a row lock. This prevents deleting a service
// that was renewed between the batch query and this delete, and ensures only one
// management instance processes the deletion
func (m *Manager) deleteExpiredPeerService(ctx context.Context, accountID, peerID, serviceID string) error {
	var svc *service.Service
	deleted := false
	err := m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		var err error
		svc, err = transaction.GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID)
		if err != nil {
			return err
		}

		if svc.Source != service.SourceEphemeral || svc.SourcePeer != peerID {
			return status.Errorf(status.PermissionDenied, "service does not match expected ephemeral owner")
		}

		if svc.Meta.LastRenewedAt != nil && time.Since(*svc.Meta.LastRenewedAt) <= exposeTTL {
			return nil
		}

		if err = transaction.DeleteService(ctx, accountID, serviceID); err != nil {
			return fmt.Errorf("delete service: %w", err)
		}
		deleted = true

		return nil
	})
	if err != nil {
		return err
	}

	if !deleted {
		return nil
	}

	peer, err := m.store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		log.WithContext(ctx).Debugf("failed to get peer %s for event metadata: %v", peerID, err)
		peer = nil
	}

	meta := addPeerInfoToEventMeta(svc.EventMeta(), peer)
	m.accountManager.StoreEvent(ctx, peerID, serviceID, accountID, activity.PeerServiceExposeExpired, meta)
	m.proxyController.SendServiceUpdateToCluster(ctx, accountID, svc.ToProtoMapping(service.Delete, "", m.proxyController.GetOIDCValidationConfig()), svc.ProxyCluster)
	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

func addPeerInfoToEventMeta(meta map[string]any, peer *nbpeer.Peer) map[string]any {
	if peer == nil {
		return meta
	}
	meta["peer_name"] = peer.Name
	if peer.IP != nil {
		meta["peer_ip"] = peer.IP.String()
	}
	return meta
}
