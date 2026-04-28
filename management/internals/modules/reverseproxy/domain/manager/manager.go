package manager

import (
	"context"
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/credentials/recordwriter"
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
	CreateCustomDomain(ctx context.Context, accountID string, domainName string, targetCluster string, validated bool, autoConfig *domain.AutoConfigureRecord) (*domain.Domain, error)
	UpdateCustomDomain(ctx context.Context, accountID string, d *domain.Domain) (*domain.Domain, error)
	DeleteCustomDomain(ctx context.Context, accountID string, domainID string) error
}

// CredentialResolver looks up a stored credential by account+ID and
// returns its decoded secret fields and provider type. The manager calls
// this when handling auto-configure to fetch the writer credentials
// without ever touching the encryption key directly.
//
// Wired from the app composition root (server.go) as a closure over
// am.ResolveCredentialSecret + secretpayload.Decode. Kept as a closure
// rather than an interface to avoid the manager package having to know
// about the credentials package.
type CredentialResolver func(ctx context.Context, accountID, credentialID string) (
	secret map[string]string, providerType string, err error,
)

// AutoConfigureRequest is the manager-layer input describing what
// credential should write the wildcard CNAME for a new custom domain.
// Mirrors the API-layer api.AutoConfigureRequest but keeps the manager
// independent of the OpenAPI types.
type AutoConfigureRequest struct {
	CredentialID string
	Provider     string
}

type proxyManager interface {
	GetActiveClusterAddresses(ctx context.Context) ([]string, error)
	ClusterSupportsCustomPorts(ctx context.Context, clusterAddr string) *bool
	ClusterRequireSubdomain(ctx context.Context, clusterAddr string) *bool
	ClusterSupportsCrowdSec(ctx context.Context, clusterAddr string) *bool
}

type Manager struct {
	store              store
	validator          domain.Validator
	proxyManager       proxyManager
	permissionsManager permissions.Manager
	accountManager     account.Manager

	// credentialResolver is set when the management server wires up the
	// auto-configure path. nil means auto-configure requests will be
	// rejected with status.Internal — useful for older deploys that
	// haven't enabled the feature.
	credentialResolver CredentialResolver
	// fqdnMutex serializes auto-configure operations per FQDN to avoid
	// double-write races on providers that don't dedupe server-side.
	fqdnMutex *fqdnMutexMap
}

func NewManager(store store, proxyMgr proxyManager, permissionsManager permissions.Manager, accountManager account.Manager, credentialResolver CredentialResolver) Manager {
	return Manager{
		store:              store,
		proxyManager:       proxyMgr,
		validator:          domain.Validator{Resolver: net.DefaultResolver},
		permissionsManager: permissionsManager,
		accountManager:     accountManager,
		credentialResolver: credentialResolver,
		fqdnMutex:          newFQDNMutexMap(),
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
		d.SupportsCrowdSec = m.proxyManager.ClusterSupportsCrowdSec(ctx, cluster)
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
		}
		// Custom domains never require a subdomain by default since
		// the account owns them and should be able to use the bare domain.
		ret = append(ret, cd)
	}

	return ret, nil
}

func (m Manager) CreateDomain(ctx context.Context, accountID, userID, domainName, targetCluster string, autoConfig *AutoConfigureRequest) (*domain.Domain, error) {
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

	// Auto-configure pre-step: if the request includes credentials,
	// write the wildcard CNAME for the user before persisting the
	// domain. On any writer failure we bail out without persisting —
	// otherwise the user would have a stuck `validated:false` row they
	// can't recover.
	var autoRecord *domain.AutoConfigureRecord
	if autoConfig != nil {
		var err error
		autoRecord, err = m.runAutoConfigure(ctx, accountID, userID, domainName, targetCluster, autoConfig)
		if err != nil {
			return nil, err
		}
	}

	// Attempt an initial validation against the specified cluster only.
	// For auto-configure this typically misses on first call (DNS
	// propagation lag) — the dashboard polls /validate after this returns.
	var validated bool
	if m.validator.IsValid(ctx, domainName, []string{targetCluster}) {
		validated = true
	}

	d, err := m.store.CreateCustomDomain(ctx, accountID, domainName, targetCluster, validated, autoRecord)
	if err != nil {
		return d, fmt.Errorf("create domain in store: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, d.ID, accountID, activity.DomainAdded, d.EventMeta())

	return d, nil
}

// runAutoConfigure fetches the credential, builds the writer, writes
// the wildcard CNAME, and audit-logs the write. Returns the metadata
// to persist on the new domain row.
func (m Manager) runAutoConfigure(ctx context.Context, accountID, userID, domainName, targetCluster string, autoConfig *AutoConfigureRequest) (*domain.AutoConfigureRecord, error) {
	if m.credentialResolver == nil {
		return nil, status.Errorf(status.Internal, "auto-configure is not enabled on this management server")
	}
	if m.fqdnMutex == nil {
		// Defensive — NewManager always sets this. A nil here means a
		// caller built a Manager{} literal directly, which is a bug.
		return nil, status.Errorf(status.Internal, "manager not properly initialized: missing fqdnMutex")
	}

	fqdn := "*." + domainName
	unlock := m.fqdnMutex.Lock(fqdn)
	defer unlock()

	secret, providerType, err := m.credentialResolver(ctx, accountID, autoConfig.CredentialID)
	if err != nil {
		return nil, mapCredentialResolveError(err)
	}
	if providerType != autoConfig.Provider {
		return nil, status.Errorf(status.InvalidArgument,
			"provider mismatch: credential is %s, request says %s", providerType, autoConfig.Provider)
	}

	writer, err := recordwriter.BuildRecordWriter(providerType, secret)
	if err != nil {
		return nil, status.Errorf(status.InvalidArgument,
			"auto-configure not supported for provider %s", providerType)
	}

	if err := writer.WriteCNAME(ctx, fqdn, targetCluster, 300); err != nil {
		return nil, mapRecordWriterError(err, providerType, fqdn)
	}

	// Audit-log the CNAME write. Distinct from DomainAdded so the audit
	// log can separately answer "did NetBird write DNS on this user's
	// behalf?" — required for security review sign-off.
	m.accountManager.StoreEvent(ctx, userID, "", accountID, activity.DomainCNAMEWritten, map[string]any{
		"domain":        domainName,
		"provider":      providerType,
		"credential_id": autoConfig.CredentialID,
		"fqdn":          fqdn,
		"target":        targetCluster,
	})

	return &domain.AutoConfigureRecord{
		CredentialID: autoConfig.CredentialID,
		Provider:     providerType,
	}, nil
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
