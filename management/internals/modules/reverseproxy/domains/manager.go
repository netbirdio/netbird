package domains

import (
	"context"
	"fmt"
)

type domainType string

const (
	domainTypeFree   domainType = "free"
	domainTypeCustom domainType = "custom"
)

type domain struct {
	ID        string
	Domain    string
	Type      domainType
	Validated bool
}

type store interface {
	GetAccountDomainNonce(ctx context.Context, accountID string) (nonce string, err error)
	GetCustomDomain(ctx context.Context, accountID string, domainID string) (domain, error)
	ListFreeDomains(ctx context.Context, accountID string) ([]string, error)
	ListCustomDomains(ctx context.Context, accountID string) ([]domain, error)
	CreateCustomDomain(ctx context.Context, accountID string, domainName string, validated bool) (domain, error)
	UpdateCustomDomain(ctx context.Context, accountID string, d domain) (domain, error)
	DeleteCustomDomain(ctx context.Context, accountID string, domainID string) error
}

type manager struct {
	store     store
	validator Validator
}

func (m manager) GetDomains(ctx context.Context, accountID string) ([]domain, error) {
	nonce, err := m.store.GetAccountDomainNonce(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account domain nonce: %w", err)
	}
	free, err := m.store.ListFreeDomains(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("list free domains: %w", err)
	}
	domains, err := m.store.ListCustomDomains(ctx, accountID)
	if err != nil {
		// TODO: check for "no records" type error. Because that is a success condition.
		return nil, fmt.Errorf("list custom domains: %w", err)
	}

	// Prepend each free domain with the account nonce and then add it to the domain
	// array to be returned.
	// This account nonce is added to free domains to prevent users being able to
	// query free domain usage across accounts and simplifies tracking free domain
	// usage across accounts.
	for _, name := range free {
		domains = append(domains, domain{
			Domain:    nonce + "." + name,
			Type:      domainTypeFree,
			Validated: true,
		})
	}
	return domains, nil
}

func (m manager) CreateDomain(ctx context.Context, accountID, domainName string) (domain, error) {
	// Attempt an initial validation; however, a failure is still acceptable for creation
	// because the user may not yet have configured their DNS records, or the DNS update
	// has not yet reached the servers that are queried by the validation resolver.
	var validated bool
	// TODO: retrieve in use reverse proxy addresses from somewhere!
	var reverseProxyAddresses []string
	if m.validator.IsValid(ctx, domainName, reverseProxyAddresses) {
		validated = true
	}

	d, err := m.store.CreateCustomDomain(ctx, accountID, domainName, validated)
	if err != nil {
		return d, fmt.Errorf("create domain in store: %w", err)
	}

	return d, nil
}

func (m manager) DeleteDomain(ctx context.Context, accountID, domainID string) error {
	if err := m.store.DeleteCustomDomain(ctx, accountID, domainID); err != nil {
		// TODO: check for "no records" type error. Because that is a success condition.
		return fmt.Errorf("delete domain from store: %w", err)
	}
	return nil
}

func (m manager) ValidateDomain(accountID, domainID string) {
	d, err := m.store.GetCustomDomain(context.Background(), accountID, domainID)
	if err != nil {
		// TODO: something? Log?
		return
	}
	// TODO: retrieve in use reverse proxy addresses from somewhere!
	var reverseProxyAddresses []string
	if m.validator.IsValid(context.Background(), d.Domain, reverseProxyAddresses) {
		d.Validated = true
		if _, err := m.store.UpdateCustomDomain(context.Background(), accountID, d); err != nil {
			// TODO: something? Log?
			return
		}
	}
}
