package domain

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/netbirdio/netbird/management/server/types"
	log "github.com/sirupsen/logrus"
)

type domainType string

const (
	TypeFree   domainType = "free"
	TypeCustom domainType = "custom"
)

type Domain struct {
	ID        string     `gorm:"unique;primaryKey;autoIncrement"`
	Domain    string     `gorm:"unique"` // Domain records must be unique, this avoids domain reuse across accounts.
	AccountID string     `gorm:"index"`
	Type      domainType `gorm:"-"`
	Validated bool
}

type store interface {
	GetAccount(ctx context.Context, accountID string) (*types.Account, error)

	GetCustomDomain(ctx context.Context, accountID string, domainID string) (*Domain, error)
	ListFreeDomains(ctx context.Context, accountID string) ([]string, error)
	ListCustomDomains(ctx context.Context, accountID string) ([]*Domain, error)
	CreateCustomDomain(ctx context.Context, accountID string, domainName string, validated bool) (*Domain, error)
	UpdateCustomDomain(ctx context.Context, accountID string, d *Domain) (*Domain, error)
	DeleteCustomDomain(ctx context.Context, accountID string, domainID string) error
}

type proxyURLProvider interface {
	GetConnectedProxyURLs() []string
}

type Manager struct {
	store            store
	validator        Validator
	proxyURLProvider proxyURLProvider
}

func NewManager(store store, proxyURLProvider proxyURLProvider) Manager {
	return Manager{
		store:            store,
		proxyURLProvider: proxyURLProvider,
		validator: Validator{
			resolver: net.DefaultResolver,
		},
	}
}

func (m Manager) GetDomains(ctx context.Context, accountID string) ([]*Domain, error) {
	domains, err := m.store.ListCustomDomains(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("list custom domains: %w", err)
	}

	var ret []*Domain

	// Add connected proxy clusters as free domains.
	// The cluster address itself is the free domain base (e.g., "eu.proxy.netbird.io").
	allowList := m.proxyURLAllowList()
	log.WithFields(log.Fields{
		"accountID":      accountID,
		"proxyAllowList": allowList,
	}).Debug("getting domains with proxy allow list")

	for _, cluster := range allowList {
		ret = append(ret, &Domain{
			Domain:    cluster,
			AccountID: accountID,
			Type:      TypeFree,
			Validated: true,
		})
	}

	// Add custom domains.
	for _, domain := range domains {
		ret = append(ret, &Domain{
			ID:        domain.ID,
			Domain:    domain.Domain,
			AccountID: accountID,
			Type:      TypeCustom,
			Validated: domain.Validated,
		})
	}

	return ret, nil
}

func (m Manager) CreateDomain(ctx context.Context, accountID, domainName string) (*Domain, error) {
	// Attempt an initial validation; however, a failure is still acceptable for creation
	// because the user may not yet have configured their DNS records, or the DNS update
	// has not yet reached the servers that are queried by the validation resolver.
	var validated bool
	if m.validator.IsValid(ctx, domainName, m.proxyURLAllowList()) {
		validated = true
	}

	d, err := m.store.CreateCustomDomain(ctx, accountID, domainName, validated)
	if err != nil {
		return d, fmt.Errorf("create domain in store: %w", err)
	}

	return d, nil
}

func (m Manager) DeleteDomain(ctx context.Context, accountID, domainID string) error {
	if err := m.store.DeleteCustomDomain(ctx, accountID, domainID); err != nil {
		// TODO: check for "no records" type error. Because that is a success condition.
		return fmt.Errorf("delete domain from store: %w", err)
	}
	return nil
}

func (m Manager) ValidateDomain(accountID, domainID string) {
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

	allowList := m.proxyURLAllowList()
	log.WithFields(log.Fields{
		"accountID":      accountID,
		"domainID":       domainID,
		"domain":         d.Domain,
		"proxyAllowList": allowList,
	}).Info("validating domain against proxy allow list")

	if m.validator.IsValid(context.Background(), d.Domain, allowList) {
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
	} else {
		log.WithFields(log.Fields{
			"accountID":      accountID,
			"domainID":       domainID,
			"domain":         d.Domain,
			"proxyAllowList": allowList,
		}).Warn("domain validation failed - CNAME does not match any connected proxy")
	}
}

// proxyURLAllowList retrieves a list of currently connected proxies and
// their URLs (as reported by the proxy servers). It performs some clean
// up on those URLs to attempt to retrieve domain names as we would
// expect to see them in a validation check.
func (m Manager) proxyURLAllowList() []string {
	var reverseProxyAddresses []string
	if m.proxyURLProvider != nil {
		reverseProxyAddresses = m.proxyURLProvider.GetConnectedProxyURLs()
	}
	var allowedProxyURLs []string
	for _, addr := range reverseProxyAddresses {
		if addr == "" {
			continue
		}
		host := extractHostFromAddress(addr)
		if host != "" {
			allowedProxyURLs = append(allowedProxyURLs, host)
		}
	}
	return allowedProxyURLs
}

// extractHostFromAddress extracts the hostname from an address string.
// It handles both URL format (https://host:port) and plain hostname (host or host:port).
func extractHostFromAddress(addr string) string {
	// If it looks like a URL with a scheme, parse it
	if strings.Contains(addr, "://") {
		proxyUrl, err := url.Parse(addr)
		if err != nil {
			log.WithError(err).Debugf("failed to parse proxy URL %s", addr)
			return ""
		}
		host, _, err := net.SplitHostPort(proxyUrl.Host)
		if err != nil {
			return proxyUrl.Host
		}
		return host
	}

	// Otherwise treat as hostname or host:port
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port, use as-is
		return addr
	}
	return host
}

// DeriveClusterFromDomain determines the proxy cluster for a given domain.
// For free domains (those ending with a known cluster suffix), the cluster is extracted from the domain.
// For custom domains, the cluster is determined by looking up the CNAME target.
func (m Manager) DeriveClusterFromDomain(ctx context.Context, domain string) (string, error) {
	allowList := m.proxyURLAllowList()
	if len(allowList) == 0 {
		return "", fmt.Errorf("no proxy clusters available")
	}

	if cluster, ok := ExtractClusterFromFreeDomain(domain, allowList); ok {
		return cluster, nil
	}

	cluster, valid := m.validator.ValidateWithCluster(ctx, domain, allowList)
	if valid {
		return cluster, nil
	}

	return "", fmt.Errorf("domain %s does not match any available proxy cluster", domain)
}
