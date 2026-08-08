package manager

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

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

const (
	// claimTTL bounds how long a domain may be held by a row that has never
	// reached Validated. Past it the claim is evicted and the name is free again.
	claimTTL = 24 * time.Hour

	// maxCustomDomainsPerAccount caps how many custom domains an account may
	// hold. Every domain turns into a certificate order against the cluster's
	// ACME issuance rate limit, which is shared by every account on it.
	maxCustomDomainsPerAccount = 100

	// maintenanceInterval is how often claims are expired and validated
	// domains are re-checked against their target cluster.
	maintenanceInterval = time.Hour

	// revalidationFailureThreshold is how many consecutive failed re-checks a
	// validated domain must accumulate before it is flipped back. A single
	// failed lookup is far more often a transient resolver problem than a
	// deliberate DNS change.
	revalidationFailureThreshold = 3
)

type store interface {
	GetAccount(ctx context.Context, accountID string) (*types.Account, error)

	GetCustomDomain(ctx context.Context, accountID string, domainID string) (*domain.Domain, error)
	ListFreeDomains(ctx context.Context, accountID string) ([]string, error)
	ListCustomDomains(ctx context.Context, accountID string) ([]*domain.Domain, error)
	ListCustomDomainsByName(ctx context.Context, domainName string) ([]*domain.Domain, error)
	ListAllCustomDomains(ctx context.Context) ([]*domain.Domain, error)
	CreateCustomDomain(ctx context.Context, accountID string, domainName string, targetCluster string, validated bool, claimedAt time.Time) (*domain.Domain, error)
	UpdateCustomDomain(ctx context.Context, accountID string, d *domain.Domain) (*domain.Domain, error)
	DeleteCustomDomain(ctx context.Context, accountID string, domainID string) error
}

type proxyManager interface {
	GetActiveClusterAddresses(ctx context.Context) ([]string, error)
	GetActiveClusterAddressesForAccount(ctx context.Context, accountID string) ([]string, error)
	ClusterSupportsCustomPorts(ctx context.Context, clusterAddr string) *bool
	ClusterRequireSubdomain(ctx context.Context, clusterAddr string) *bool
	ClusterSupportsCrowdSec(ctx context.Context, clusterAddr string) *bool
	ClusterSupportsPrivate(ctx context.Context, clusterAddr string) *bool
}

// failureTracker counts consecutive revalidation failures per domain ID. It is
// held by pointer so copies of the value-typed Manager share one instance.
type failureTracker struct {
	mu     sync.Mutex
	counts map[string]int
}

// record increments the failure count for a domain and returns the new total.
func (f *failureTracker) record(domainID string) int {
	if f == nil {
		return 1
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[domainID]++
	return f.counts[domainID]
}

// clear forgets the failure history of a domain.
func (f *failureTracker) clear(domainID string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.counts, domainID)
}

type Manager struct {
	store              store
	validator          domain.Validator
	proxyManager       proxyManager
	permissionsManager permissions.Manager
	accountManager     account.Manager
	now                func() time.Time
	revalidationFails  *failureTracker
}

func NewManager(store store, proxyMgr proxyManager, permissionsManager permissions.Manager, accountManager account.Manager) Manager {
	return Manager{
		store:              store,
		proxyManager:       proxyMgr,
		validator:          domain.Validator{Resolver: net.DefaultResolver},
		permissionsManager: permissionsManager,
		accountManager:     accountManager,
		now:                time.Now,
		revalidationFails:  &failureTracker{counts: make(map[string]int)},
	}
}

// currentTime returns the manager's clock, tolerating a zero-valued Manager
// built directly in tests.
func (m Manager) currentTime() time.Time {
	if m.now == nil {
		return time.Now()
	}
	return m.now().UTC()
}

func (m Manager) GetDomains(ctx context.Context, accountID, userID string) ([]*domain.Domain, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
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
	// For BYOP accounts, only their own cluster is returned; otherwise shared clusters.
	allowList, err := m.getClusterAllowList(ctx, accountID)
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
		d.SupportsCrowdSec = m.proxyManager.ClusterSupportsCrowdSec(ctx, cluster)
		d.SupportsPrivate = m.proxyManager.ClusterSupportsPrivate(ctx, cluster)
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
			cd.SupportsCrowdSec = m.proxyManager.ClusterSupportsCrowdSec(ctx, d.TargetCluster)
			cd.SupportsPrivate = m.proxyManager.ClusterSupportsPrivate(ctx, d.TargetCluster)
		}
		// Custom domains never require a subdomain by default since
		// the account owns them and should be able to use the bare domain.
		ret = append(ret, cd)
	}

	return ret, nil
}

func (m Manager) CreateDomain(ctx context.Context, accountID, userID, domainName, targetCluster string) (*domain.Domain, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	// Verify the target cluster is in the available clusters for this account
	allowList, err := m.getClusterAllowList(ctx, accountID)
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

	if err := m.checkAccountQuota(ctx, accountID, domainName); err != nil {
		return nil, err
	}

	if err := m.checkDomainClaimable(ctx, accountID, domainName); err != nil {
		return nil, err
	}

	// Attempt an initial validation against the specified cluster only
	var validated bool
	if m.validator.IsValid(ctx, domainName, []string{targetCluster}) {
		validated = true
	}

	d, err := m.store.CreateCustomDomain(ctx, accountID, domainName, targetCluster, validated, m.currentTime())
	if err != nil {
		return nil, fmt.Errorf("create domain in store: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, d.ID, accountID, activity.DomainAdded, d.EventMeta())

	return d, nil
}

// checkAccountQuota rejects a new claim once the account already holds the
// maximum number of custom domains, or already holds this one.
func (m Manager) checkAccountQuota(ctx context.Context, accountID, domainName string) error {
	owned, err := m.store.ListCustomDomains(ctx, accountID)
	if err != nil {
		return fmt.Errorf("list custom domains: %w", err)
	}

	for _, d := range owned {
		if d.Domain == domainName {
			return status.Errorf(status.AlreadyExists, "domain %s is already registered", domainName)
		}
	}

	if len(owned) >= maxCustomDomainsPerAccount {
		return status.Errorf(status.PreconditionFailed, "account has reached the maximum of %d custom domains", maxCustomDomainsPerAccount)
	}

	return nil
}

// checkDomainClaimable rejects a claim on a domain another account already
// serves. Unvalidated claims by other accounts do not block: proving control of
// the DNS zone is what settles ownership, and until then nobody has. The error
// deliberately says nothing about who holds the domain.
func (m Manager) checkDomainClaimable(ctx context.Context, accountID, domainName string) error {
	holders, err := m.store.ListCustomDomainsByName(ctx, domainName)
	if err != nil {
		return fmt.Errorf("list domain holders: %w", err)
	}

	for _, d := range holders {
		if d.AccountID != accountID && d.Validated {
			return status.Errorf(status.AlreadyExists, "domain %s is already in use", domainName)
		}
	}

	return nil
}

func (m Manager) DeleteDomain(ctx context.Context, accountID, userID, domainID string) error {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Delete)
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
	ok, _, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Create)
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
		}).Error("validate domain: permission denied")
		return
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

	if !m.validator.IsValid(context.Background(), d.Domain, []string{targetCluster}) {
		log.WithFields(log.Fields{
			"accountID":     accountID,
			"domainID":      domainID,
			"domain":        d.Domain,
			"targetCluster": targetCluster,
		}).Warn("domain validation failed - CNAME does not match target cluster")
		return
	}

	// The CNAME proves control of the zone but says nothing about which account
	// asked, so an account that is late to validate a name another one already
	// serves must not take it over.
	if err := m.checkDomainClaimable(context.Background(), accountID, d.Domain); err != nil {
		log.WithFields(log.Fields{
			"accountID": accountID,
			"domainID":  domainID,
			"domain":    d.Domain,
		}).WithError(err).Warn("domain validation refused")
		return
	}

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
	m.revalidationFails.clear(domainID)

	m.accountManager.StoreEvent(context.Background(), userID, domainID, accountID, activity.DomainValidated, d.EventMeta())
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
	allowList, err := m.getClusterAllowList(ctx, accountID)
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

	targetCluster, match := extractClusterFromCustomDomains(domain, customDomains)
	switch match {
	case customDomainValidated:
		return targetCluster, nil
	case customDomainUnvalidated:
		return "", status.Errorf(status.PreconditionFailed, "domain %s is not validated", domain)
	}

	return "", fmt.Errorf("domain %s does not match any available proxy cluster", domain)
}

// IsDomainValidated reports whether the account is currently allowed to serve
// the domain: free cluster domains always are, custom domains only once their
// CNAME validation has succeeded. Any lookup failure denies.
func (m Manager) IsDomainValidated(ctx context.Context, accountID, domain string) bool {
	if _, err := m.DeriveClusterFromDomain(ctx, accountID, domain); err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"accountID": accountID,
			"domain":    domain,
		}).WithError(err).Debug("domain is not servable")
		return false
	}
	return true
}

func (m Manager) getClusterAllowList(ctx context.Context, accountID string) ([]string, error) {
	byopAddresses, err := m.proxyManager.GetActiveClusterAddressesForAccount(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get BYOP cluster addresses: %w", err)
	}
	publicAddresses, err := m.proxyManager.GetActiveClusterAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("get public cluster addresses: %w", err)
	}
	seen := make(map[string]struct{}, len(byopAddresses)+len(publicAddresses))
	merged := make([]string, 0, len(byopAddresses)+len(publicAddresses))
	for _, addr := range byopAddresses {
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		merged = append(merged, addr)
	}
	for _, addr := range publicAddresses {
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		merged = append(merged, addr)
	}
	return merged, nil
}

// customDomainMatch describes how a service domain relates to the account's
// custom domain rows.
type customDomainMatch int

const (
	customDomainNoMatch customDomainMatch = iota
	customDomainUnvalidated
	customDomainValidated
)

// extractClusterFromCustomDomains finds the longest custom domain covering the
// service domain and reports its target cluster. Only a validated row yields a
// cluster: a row whose CNAME check has never succeeded proves no control over
// the name, so serving traffic for it would route a hostname the account has
// not shown it owns.
func extractClusterFromCustomDomains(serviceDomain string, customDomains []*domain.Domain) (string, customDomainMatch) {
	bestCluster := ""
	bestLen := -1
	matched := false
	for _, cd := range customDomains {
		if serviceDomain != cd.Domain && !strings.HasSuffix(serviceDomain, "."+cd.Domain) {
			continue
		}
		matched = true
		if !cd.Validated {
			continue
		}
		if l := len(cd.Domain); l > bestLen {
			bestLen = l
			bestCluster = cd.TargetCluster
		}
	}

	switch {
	case bestLen >= 0:
		return bestCluster, customDomainValidated
	case matched:
		return "", customDomainUnvalidated
	default:
		return "", customDomainNoMatch
	}
}

// StartMaintenance runs claim expiry and revalidation until the context is
// cancelled. A first pass runs immediately so a restart does not leave stale
// claims parked for a whole interval.
func (m Manager) StartMaintenance(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(maintenanceInterval)
		defer ticker.Stop()

		m.RunMaintenance(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.RunMaintenance(ctx)
			}
		}
	}()
}

// RunMaintenance evicts expired claims and re-checks validated domains once.
func (m Manager) RunMaintenance(ctx context.Context) {
	domains, err := m.store.ListAllCustomDomains(ctx)
	if err != nil {
		log.WithContext(ctx).WithError(err).Error("list custom domains for maintenance")
		return
	}

	for _, d := range domains {
		if !d.Validated {
			m.evictExpiredClaim(ctx, d)
			continue
		}
		m.revalidate(ctx, d)
	}
}

// evictExpiredClaim deletes an unvalidated row that has held its name for
// longer than claimTTL. A row with no claim date is left alone: it predates the
// column and the migration backfill dates it from the upgrade.
func (m Manager) evictExpiredClaim(ctx context.Context, d *domain.Domain) {
	if d.ClaimedAt.IsZero() || m.currentTime().Sub(d.ClaimedAt) <= claimTTL {
		return
	}

	if err := m.store.DeleteCustomDomain(ctx, d.AccountID, d.ID); err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"accountID": d.AccountID,
			"domainID":  d.ID,
			"domain":    d.Domain,
		}).WithError(err).Error("evict expired domain claim")
		return
	}

	m.revalidationFails.clear(d.ID)
	log.WithContext(ctx).WithFields(log.Fields{
		"accountID": d.AccountID,
		"domainID":  d.ID,
		"domain":    d.Domain,
	}).Info("evicted domain claim that was never validated")

	m.accountManager.StoreEvent(ctx, activity.SystemInitiator, d.ID, d.AccountID, activity.DomainDeleted, d.EventMeta())
}

// revalidate re-checks a validated domain against its target cluster and, once
// the check has failed revalidationFailureThreshold times in a row, marks it
// unvalidated and restarts its claim window. Without this an account that moves
// its DNS elsewhere keeps the name reserved forever.
func (m Manager) revalidate(ctx context.Context, d *domain.Domain) {
	if d.TargetCluster == "" {
		return
	}

	if m.validator.IsValid(ctx, d.Domain, []string{d.TargetCluster}) {
		m.revalidationFails.clear(d.ID)
		return
	}

	failures := m.revalidationFails.record(d.ID)
	if failures < revalidationFailureThreshold {
		log.WithContext(ctx).WithFields(log.Fields{
			"accountID": d.AccountID,
			"domainID":  d.ID,
			"domain":    d.Domain,
			"failures":  failures,
		}).Warn("domain revalidation failed, waiting for confirmation")
		return
	}

	d.Validated = false
	d.ClaimedAt = m.currentTime()
	if _, err := m.store.UpdateCustomDomain(ctx, d.AccountID, d); err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"accountID": d.AccountID,
			"domainID":  d.ID,
			"domain":    d.Domain,
		}).WithError(err).Error("mark domain unvalidated after revalidation failure")
		return
	}

	m.revalidationFails.clear(d.ID)
	log.WithContext(ctx).WithFields(log.Fields{
		"accountID":     d.AccountID,
		"domainID":      d.ID,
		"domain":        d.Domain,
		"targetCluster": d.TargetCluster,
	}).Warn("domain marked unvalidated, CNAME no longer points at the target cluster")

	m.accountManager.StoreEvent(ctx, activity.SystemInitiator, d.ID, d.AccountID, activity.DomainInvalidated, d.EventMeta())
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
