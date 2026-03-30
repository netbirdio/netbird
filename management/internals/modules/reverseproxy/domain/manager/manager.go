package manager

import (
	"context"
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

type store interface {
	GetAccount(ctx context.Context, accountID string) (*types.Account, error)

	GetCustomDomain(ctx context.Context, accountID string, domainID string) (*domain.Domain, error)
	ListFreeDomains(ctx context.Context, accountID string) ([]string, error)
	ListCustomDomains(ctx context.Context, accountID string) ([]*domain.Domain, error)
	CreateCustomDomain(ctx context.Context, accountID string, domainName string, targetCluster string, validated bool) (*domain.Domain, error)
	UpdateCustomDomain(ctx context.Context, accountID string, d *domain.Domain) (*domain.Domain, error)
	DeleteCustomDomain(ctx context.Context, accountID string, domainID string) error
}

type proxyManager interface {
	GetActiveClusterAddresses(ctx context.Context) ([]string, error)
	ClusterSupportsCustomPorts(ctx context.Context, clusterAddr string) *bool
	ClusterRequireSubdomain(ctx context.Context, clusterAddr string) *bool
}

type Manager struct {
	store              store
	validator          domain.Validator
	proxyManager       proxyManager
	permissionsManager permissions.Manager
	accountManager     account.Manager
}

func NewManager(store store, proxyMgr proxyManager, permissionsManager permissions.Manager, accountManager account.Manager) Manager {
	return Manager{
		store:              store,
		proxyManager:       proxyMgr,
		validator:          domain.Validator{Resolver: net.DefaultResolver},
		permissionsManager: permissionsManager,
		accountManager:     accountManager,
	}
}

func (m Manager) GetDomains(ctx context.Context, accountID, userID string) ([]*domain.Domain, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	domains, err := m.store.ListCustomDomains(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("list custom domains: %w", err)
	}

	var ret []*domain.Domain

	// Add connected proxy clusters as free domains.
	// The cluster address itself is the free domain base (e.g., "eu.proxy.netbird.io").
	allowList, err := m.proxyManager.GetActiveClusterAddresses(ctx)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get active proxy cluster addresses: %v", err)
		return nil, err
	}
	log.WithContext(ctx).WithFields(log.Fields{
		"accountID":      accountID,
		"proxyAllowList": allowList,
	}).Debug("getting domains with proxy allow list")

	for _, cluster := range allowList {
		d := &domain.Domain{
			Domain:    cluster,
			AccountID: accountID,
			Type:      domain.TypeFree,
			Validated: true,
		}
		d.SupportsCustomPorts = m.proxyManager.ClusterSupportsCustomPorts(ctx, cluster)
		d.RequireSubdomain = m.proxyManager.ClusterRequireSubdomain(ctx, cluster)
		ret = append(ret, d)
	}

	// Add custom domains.
	for _, d := range domains {
		cd := &domain.Domain{
			ID:            d.ID,
			Domain:        d.Domain,
			AccountID:     accountID,
			TargetCluster: d.TargetCluster,
			Type:          domain.TypeCustom,
			Validated:     d.Validated,
		}
		if d.TargetCluster != "" {
			cd.SupportsCustomPorts = m.proxyManager.ClusterSupportsCustomPorts(ctx, d.TargetCluster)
		}
		// Custom domains never require a subdomain by default since
		// the account owns them and should be able to use the bare domain.
		ret = append(ret, cd)
	}

	return ret, nil
}

func (m Manager) CreateDomain(ctx context.Context, accountID, userID, domainName, targetCluster string) (*domain.Domain, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	// Verify the target cluster is in the available clusters
	allowList, err := m.proxyManager.GetActiveClusterAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active proxy cluster addresses: %w", err)
	}
	clusterValid := false
	for _, cluster := range allowList {
		if cluster == targetCluster {
			clusterValid = true
			break
		}
	}
	if !clusterValid {
		return nil, fmt.Errorf("target cluster %s is not available", targetCluster)
	}

	// Attempt an initial validation against the specified cluster only
	var validated bool
	if m.validator.IsValid(ctx, domainName, []string{targetCluster}) {
		validated = true
	}

	d, err := m.store.CreateCustomDomain(ctx, accountID, domainName, targetCluster, validated)
	if err != nil {
		return d, fmt.Errorf("create domain in store: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, d.ID, accountID, activity.DomainAdded, d.EventMeta())

	return d, nil
}

func (m Manager) DeleteDomain(ctx context.Context, accountID, userID, domainID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	d, err := m.store.GetCustomDomain(ctx, accountID, domainID)
	if err != nil {
		return fmt.Errorf("get domain from store: %w", err)
	}

	if err := m.store.DeleteCustomDomain(ctx, accountID, domainID); err != nil {
		// TODO: check for "no records" type error. Because that is a success condition.
		return fmt.Errorf("delete domain from store: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, domainID, accountID, activity.DomainDeleted, d.EventMeta())

	return nil
}

func (m Manager) ValidateDomain(ctx context.Context, accountID, userID, domainID string) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Create)
	if err != nil {
		log.WithFields(log.Fields{
			"accountID": accountID,
			"domainID":  domainID,
		}).WithError(err).Error("validate domain")
		return
	}
	if !ok {
		log.WithFields(log.Fields{
			"accountID": accountID,
			"domainID":  domainID,
		}).WithError(err).Error("validate domain")
	}

	log.WithFields(log.Fields{
		"accountID": accountID,
		"domainID":  domainID,
	}).Info("starting domain validation")

	d, err := m.store.GetCustomDomain(context.Background(), accountID, domainID)
	if err != nil {
		log.WithFields(log.Fields{
			"accountID": accountID,
			"domainID":  domainID,
		}).WithError(err).Error("get custom domain from store")
		return
	}

	// Validate only against the domain's target cluster
	targetCluster := d.TargetCluster
	if targetCluster == "" {
		log.WithFields(log.Fields{
			"accountID": accountID,
			"domainID":  domainID,
			"domain":    d.Domain,
		}).Warn("domain has no target cluster set, skipping validation")
		return
	}

	log.WithFields(log.Fields{
		"accountID":     accountID,
		"domainID":      domainID,
		"domain":        d.Domain,
		"targetCluster": targetCluster,
	}).Info("validating domain against target cluster")

	if m.validator.IsValid(context.Background(), d.Domain, []string{targetCluster}) {
		log.WithFields(log.Fields{
			"accountID": accountID,
			"domainID":  domainID,
			"domain":    d.Domain,
		}).Info("domain validated successfully")
		d.Validated = true
		if _, err := m.store.UpdateCustomDomain(context.Background(), accountID, d); err != nil {
			log.WithFields(log.Fields{
				"accountID": accountID,
				"domainID":  domainID,
				"domain":    d.Domain,
			}).WithError(err).Error("update custom domain in store")
			return
		}

		m.accountManager.StoreEvent(context.Background(), userID, domainID, accountID, activity.DomainValidated, d.EventMeta())
	} else {
		log.WithFields(log.Fields{
			"accountID":     accountID,
			"domainID":      domainID,
			"domain":        d.Domain,
			"targetCluster": targetCluster,
		}).Warn("domain validation failed - CNAME does not match target cluster")
	}
}

// GetClusterDomains returns a list of proxy cluster domains.
func (m Manager) GetClusterDomains() []string {
	if m.proxyManager == nil {
		return nil
	}
	addresses, err := m.proxyManager.GetActiveClusterAddresses(context.Background())
	if err != nil {
		return nil
	}
	return addresses
}

// DeriveClusterFromDomain determines the proxy cluster for a given domain.
// For free domains (those ending with a known cluster suffix), the cluster is extracted from the domain.
// For custom domains, the cluster is determined by checking the registered custom domain's target cluster.
func (m Manager) DeriveClusterFromDomain(ctx context.Context, accountID, domain string) (string, error) {
	allowList, err := m.proxyManager.GetActiveClusterAddresses(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get active proxy cluster addresses: %w", err)
	}
	if len(allowList) == 0 {
		return "", fmt.Errorf("no proxy clusters available")
	}

	if cluster, ok := ExtractClusterFromFreeDomain(domain, allowList); ok {
		return cluster, nil
	}

	customDomains, err := m.store.ListCustomDomains(ctx, accountID)
	if err != nil {
		return "", fmt.Errorf("list custom domains: %w", err)
	}

	targetCluster, valid := extractClusterFromCustomDomains(domain, customDomains)
	if valid {
		return targetCluster, nil
	}

	return "", fmt.Errorf("domain %s does not match any available proxy cluster", domain)
}

func extractClusterFromCustomDomains(serviceDomain string, customDomains []*domain.Domain) (string, bool) {
	bestCluster := ""
	bestLen := -1
	for _, cd := range customDomains {
		if serviceDomain != cd.Domain && !strings.HasSuffix(serviceDomain, "."+cd.Domain) {
			continue
		}
		if l := len(cd.Domain); l > bestLen {
			bestLen = l
			bestCluster = cd.TargetCluster
		}
	}
	return bestCluster, bestLen >= 0
}

// ExtractClusterFromFreeDomain extracts the cluster address from a free domain.
// Free domains have the format: <name>.<nonce>.<cluster> (e.g., myapp.abc123.eu.proxy.netbird.io)
// It matches the domain suffix against available clusters and returns the matching cluster.
func ExtractClusterFromFreeDomain(domain string, availableClusters []string) (string, bool) {
	for _, cluster := range availableClusters {
		if domain == cluster || strings.HasSuffix(domain, "."+cluster) {
			return cluster, true
		}
	}
	return "", false
}
