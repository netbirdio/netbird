package migration

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
)

const legacyServiceDomainIndex = "idx_services_domain"

type reverseProxyServiceDomain struct {
	ID           string
	AccountID    string
	Domain       string
	Mode         string
	ProxyCluster string
	ListenPort   uint16
}

type reverseProxyPortMappingKind struct {
	ServiceID       string
	Protocol        string
	ListenPortStart uint16
	ListenPortEnd   uint16
}

type reverseProxyTLSListener struct {
	ServiceID string
	Domain    string
	Cluster   string
	Start     uint16
	End       uint16
}

// PrepareReverseProxySharedDomains canonicalizes existing service hostnames
// and removes the legacy global unique(domain) index before AutoMigrate creates
// its non-unique replacement. Canonically duplicate HTTP owners are rejected
// before any schema mutation so startup cannot make ownership ambiguous.
func PrepareReverseProxySharedDomains(ctx context.Context, db *gorm.DB) error {
	if !db.Migrator().HasTable(&rpservice.Service{}) || !db.Migrator().HasColumn(&rpservice.Service{}, "domain") {
		log.WithContext(ctx).Debug("reverse-proxy services table is incomplete, no shared-domain preparation needed")
		return nil
	}

	rows, hasAccountID, err := loadReverseProxyServiceDomains(db)
	if err != nil {
		return fmt.Errorf("load reverse-proxy service domains: %w", err)
	}

	canonicalByID := make(map[string]string, len(rows))
	httpOwners := make(map[string]string)
	domainAccounts := make(map[string]string)
	mappedServices, mappedTLSListeners, err := reverseProxyMappingKinds(db)
	if err != nil {
		return err
	}

	tlsListeners := make([]reverseProxyTLSListener, 0)
	tlsOwners := make(map[string][]string)
	for _, row := range rows {
		canonical, err := rpservice.CanonicalDomain(row.Domain)
		if err != nil {
			return fmt.Errorf("canonicalize reverse-proxy service %s domain: %w", row.ID, err)
		}
		canonicalByID[row.ID] = canonical
		if canonical != "" && hasAccountID {
			if accountID, ok := domainAccounts[canonical]; ok && accountID != row.AccountID {
				return fmt.Errorf("canonical domain %q is owned by multiple accounts %q and %q", canonical, accountID, row.AccountID)
			}
			domainAccounts[canonical] = row.AccountID
		}
		_, hasMappings := mappedServices[row.ID]
		if canonical == "" || rpservice.IsL4Protocol(row.Mode) || hasMappings {
			if canonical != "" {
				if row.Mode == rpservice.ModeTLS {
					listener := reverseProxyTLSListener{
						ServiceID: row.ID,
						Domain:    canonical,
						Cluster:   row.ProxyCluster,
						Start:     row.ListenPort,
						End:       row.ListenPort,
					}
					tlsListeners = append(tlsListeners, listener)
					tlsOwners[canonical] = appendUnique(tlsOwners[canonical], row.ID)
				}
				for _, mapping := range mappedTLSListeners[row.ID] {
					mapping.Domain = canonical
					mapping.Cluster = row.ProxyCluster
					tlsListeners = append(tlsListeners, mapping)
					tlsOwners[canonical] = appendUnique(tlsOwners[canonical], row.ID)
				}
			}
			continue
		}
		if owner, ok := httpOwners[canonical]; ok && owner != row.ID {
			return fmt.Errorf("canonical domain %q is owned by multiple HTTP services %s and %s", canonical, owner, row.ID)
		}
		httpOwners[canonical] = row.ID
	}
	for canonical, httpOwner := range httpOwners {
		if tlsOwnerIDs := tlsOwners[canonical]; len(tlsOwnerIDs) > 0 {
			return fmt.Errorf("canonical domain %q is shared by HTTP service %s and TLS passthrough service %s", canonical, httpOwner, tlsOwnerIDs[0])
		}
	}
	if err := validateCanonicalTLSListeners(tlsListeners); err != nil {
		return err
	}

	if err := DropIndex[rpservice.Service](ctx, db, legacyServiceDomainIndex); err != nil {
		return err
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		for _, row := range rows {
			canonical := canonicalByID[row.ID]
			if canonical == row.Domain {
				continue
			}
			if err := tx.Model(&rpservice.Service{}).Where("id = ?", row.ID).UpdateColumn("domain", canonical).Error; err != nil {
				return fmt.Errorf("update reverse-proxy service %s canonical domain: %w", row.ID, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

// BackfillReverseProxyHTTPDomains populates the nullable concurrency key added
// by AutoMigrate. Multiple L4 rows retain NULL while HTTP rows receive their
// canonical hostname and are protected by the unique index.
func BackfillReverseProxyHTTPDomains(ctx context.Context, db *gorm.DB) error {
	if !db.Migrator().HasTable(&rpservice.Service{}) || !db.Migrator().HasColumn(&rpservice.Service{}, "http_domain") {
		log.WithContext(ctx).Debug("reverse-proxy HTTP ownership column is absent, no backfill needed")
		return nil
	}

	rows, _, err := loadReverseProxyServiceDomains(db)
	if err != nil {
		return fmt.Errorf("load reverse-proxy HTTP ownership domains: %w", err)
	}
	mappedServices, _, err := reverseProxyMappingKinds(db)
	if err != nil {
		return err
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		for _, row := range rows {
			var httpDomain any
			_, hasMappings := mappedServices[row.ID]
			if row.Domain != "" && !rpservice.IsL4Protocol(row.Mode) && !hasMappings {
				httpDomain = row.Domain
			}
			if err := tx.Model(&rpservice.Service{}).Where("id = ?", row.ID).UpdateColumn("http_domain", httpDomain).Error; err != nil {
				return fmt.Errorf("backfill reverse-proxy service %s HTTP domain: %w", row.ID, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func loadReverseProxyServiceDomains(db *gorm.DB) ([]reverseProxyServiceDomain, bool, error) {
	columns := []string{"id", "domain"}
	hasMode := db.Migrator().HasColumn(&rpservice.Service{}, "mode")
	hasAccountID := db.Migrator().HasColumn(&rpservice.Service{}, "account_id")
	if hasAccountID {
		columns = append(columns, "account_id")
	}
	if hasMode {
		columns = append(columns, "mode")
	}
	if db.Migrator().HasColumn(&rpservice.Service{}, "proxy_cluster") {
		columns = append(columns, "proxy_cluster")
	}
	if db.Migrator().HasColumn(&rpservice.Service{}, "listen_port") {
		columns = append(columns, "listen_port")
	}

	var rows []reverseProxyServiceDomain
	if err := db.Table("services").Select(strings.Join(columns, ", ")).Find(&rows).Error; err != nil {
		return nil, false, err
	}
	if !hasMode {
		for i := range rows {
			rows[i].Mode = rpservice.ModeHTTP
		}
	}
	return rows, hasAccountID, nil
}

func reverseProxyMappingKinds(db *gorm.DB) (mappedServices map[string]struct{}, tlsListeners map[string][]reverseProxyTLSListener, err error) {
	mappedServices = make(map[string]struct{})
	tlsListeners = make(map[string][]reverseProxyTLSListener)
	if !db.Migrator().HasTable(&rpservice.PortMapping{}) {
		return mappedServices, tlsListeners, nil
	}
	if !db.Migrator().HasColumn(&rpservice.PortMapping{}, "service_id") ||
		!db.Migrator().HasColumn(&rpservice.PortMapping{}, "protocol") {
		return mappedServices, tlsListeners, nil
	}

	columns := []string{"service_id", "protocol"}
	hasStart := db.Migrator().HasColumn(&rpservice.PortMapping{}, "listen_port_start")
	hasEnd := db.Migrator().HasColumn(&rpservice.PortMapping{}, "listen_port_end")
	if hasStart {
		columns = append(columns, "listen_port_start")
	}
	if hasEnd {
		columns = append(columns, "listen_port_end")
	}
	var mappings []reverseProxyPortMappingKind
	if err := db.Model(&rpservice.PortMapping{}).Select(strings.Join(columns, ", ")).Find(&mappings).Error; err != nil {
		return nil, nil, fmt.Errorf("load reverse-proxy port mapping protocols: %w", err)
	}
	for _, mapping := range mappings {
		mappedServices[mapping.ServiceID] = struct{}{}
		if mapping.Protocol == rpservice.ModeTLS {
			end := mapping.ListenPortEnd
			if !hasEnd || end == 0 {
				end = mapping.ListenPortStart
			}
			tlsListeners[mapping.ServiceID] = append(tlsListeners[mapping.ServiceID], reverseProxyTLSListener{
				ServiceID: mapping.ServiceID,
				Start:     mapping.ListenPortStart,
				End:       end,
			})
		}
	}
	return mappedServices, tlsListeners, nil
}

func validateCanonicalTLSListeners(listeners []reverseProxyTLSListener) error {
	for i, left := range listeners {
		for _, right := range listeners[i+1:] {
			if left.ServiceID == right.ServiceID || left.Domain != right.Domain || left.Cluster != right.Cluster {
				continue
			}
			if left.Start <= right.End && right.Start <= left.End {
				return fmt.Errorf(
					"canonical domain %q has overlapping TLS passthrough listeners for services %s and %s on cluster %q (%d-%d and %d-%d)",
					left.Domain, left.ServiceID, right.ServiceID, left.Cluster, left.Start, left.End, right.Start, right.End,
				)
			}
		}
	}
	return nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
