package migration

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// agentNetworkSettingsMigration is a local view of the agent_network_settings
// table spanning both the legacy identity columns (cluster, subdomain) and
// their replacement (domain, proxy_address), so the migrator can address all
// four during the reshape without importing the current model.
type agentNetworkSettingsMigration struct {
	AccountID    string `gorm:"primaryKey"`
	Cluster      string
	Subdomain    string
	Domain       string `gorm:"type:varchar(255)"`
	ProxyAddress string `gorm:"type:varchar(255)"`
}

func (agentNetworkSettingsMigration) TableName() string { return "agent_network_settings" }

// MigrateAgentNetworkSettingsToDomain reshapes agent_network_settings from the
// legacy (cluster, subdomain) identity columns to (domain, proxy_address):
// domain becomes `<subdomain>.<cluster>` — the endpoint hostname the old
// columns derived — and proxy_address becomes the cluster address, preserving
// which proxy serves the account. Runs before AutoMigrate, which then creates
// the unique index on the freshly backfilled domain column.
//
// A legacy row missing either half cannot be given an endpoint; the old
// bootstrap always wrote both, so such a row indicates corruption and the
// migration fails loudly rather than leaving an empty domain to collide with
// the unique index confusingly.
//
// The transaction is real only on sqlite and postgres, where DDL is
// transactional. MySQL implicitly commits around every ALTER TABLE, so there
// each step stands alone; what makes an interrupted run resumable on MySQL is
// that every step is guarded by the schema state it changes — the entry check
// fires while either legacy column remains, the adds skip existing columns,
// the backfill and its loud-failure check run only while the legacy cluster
// column exists (they provably completed before any drop), and each drop
// skips what is already gone.
func MigrateAgentNetworkSettingsToDomain(ctx context.Context, db *gorm.DB) error {
	model := &agentNetworkSettingsMigration{}
	migrator := db.Migrator()

	if !migrator.HasTable(model) {
		return nil
	}
	hasCluster := migrator.HasColumn(model, "cluster")
	if !hasCluster && !migrator.HasColumn(model, "subdomain") {
		// Fresh schema or already migrated — nothing to reshape.
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		txMigrator := tx.Migrator()
		for _, field := range []string{"Domain", "ProxyAddress"} {
			if !txMigrator.HasColumn(model, field) {
				if err := txMigrator.AddColumn(model, field); err != nil {
					return fmt.Errorf("add %s column to agent_network_settings: %w", field, err)
				}
			}
		}

		if hasCluster {
			// The legacy bootstrap stored the cluster as the caller spelled
			// it, trimmed but never folded, while every reader of these
			// columns matches exactly against canonical lowercase: proxy
			// addresses are canonicalised at connect, and the proxy's host
			// map is keyed by the domain verbatim. Fold here so the reshaped
			// row is addressable, rather than copying a spelling nothing
			// will match.
			concat := "LOWER(subdomain || '.' || cluster)"
			if tx.Name() == "mysql" {
				concat = "LOWER(CONCAT(subdomain, '.', cluster))"
			}
			res := tx.Exec(fmt.Sprintf(
				"UPDATE agent_network_settings SET domain = %s, proxy_address = LOWER(cluster) WHERE (domain IS NULL OR domain = '') AND cluster <> '' AND subdomain <> ''",
				concat,
			))
			if res.Error != nil {
				return fmt.Errorf("backfill agent_network_settings domain: %w", res.Error)
			}

			var unmigratable int64
			if err := tx.Model(model).Where("domain IS NULL OR domain = ''").Count(&unmigratable).Error; err != nil {
				return fmt.Errorf("count unmigratable agent_network_settings rows: %w", err)
			}
			if unmigratable > 0 {
				return fmt.Errorf(
					"%d agent_network_settings row(s) have no cluster/subdomain to derive an endpoint from; resolve them manually before upgrading",
					unmigratable,
				)
			}
			if err := failOnDuplicateAgentNetworkDomains(tx); err != nil {
				return err
			}

			if res.RowsAffected > 0 {
				log.WithContext(ctx).Infof("migrated %d agent_network_settings row(s) to domain/proxy_address", res.RowsAffected)
			}
		}

		if txMigrator.HasIndex(model, "idx_agent_network_settings_cluster_subdomain") {
			if err := txMigrator.DropIndex(model, "idx_agent_network_settings_cluster_subdomain"); err != nil {
				return fmt.Errorf("drop legacy agent_network_settings index: %w", err)
			}
		}
		for _, field := range []string{"Cluster", "Subdomain"} {
			if txMigrator.HasColumn(model, field) {
				if err := txMigrator.DropColumn(model, field); err != nil {
					return fmt.Errorf("drop legacy agent_network_settings column %s: %w", field, err)
				}
			}
		}

		return nil
	})
}

// agentNetworkSettingsIdentity is the post-reshape view of the two identity
// columns, enough for the normaliser to address the table without importing
// the current model.
type agentNetworkSettingsIdentity struct {
	AccountID    string `gorm:"primaryKey"`
	Domain       string `gorm:"type:varchar(255)"`
	ProxyAddress string `gorm:"type:varchar(255)"`
}

func (agentNetworkSettingsIdentity) TableName() string { return "agent_network_settings" }

// NormalizeAgentNetworkSettingsIdentity lowercases domain and proxy_address on
// rows already reshaped by a release whose backfill copied the legacy cluster
// spelling verbatim.
//
// Every reader of these columns matches exactly against canonical lowercase:
// the gateway-pin check a proxy registration runs and cluster-scoped mapping
// synthesis look proxy_address up by the canonical address, the domain lookup
// is followed by an exact Go compare, and the proxy's host map is keyed by the
// domain verbatim. A row that kept capitals is invisible to all of them, so
// the value is repaired where it is stored rather than folded on every read.
//
// MySQL needs the predicate spelled byte-wise: under its default
// case-insensitive collation `domain <> LOWER(domain)` is false for every row,
// which would leave the rows unrepaired while the Go-side compares still miss
// them. Idempotent: the predicate selects only rows that would change, one
// pass over a table holding one row per account. Runs after the reshape, so
// the columns exist whenever the table does.
func NormalizeAgentNetworkSettingsIdentity(ctx context.Context, db *gorm.DB) error {
	model := &agentNetworkSettingsIdentity{}
	migrator := db.Migrator()

	if !migrator.HasTable(model) || !migrator.HasColumn(model, "Domain") || !migrator.HasColumn(model, "ProxyAddress") {
		return nil
	}

	if err := failOnDuplicateAgentNetworkDomains(db); err != nil {
		return err
	}

	predicate := "domain <> LOWER(domain) OR proxy_address <> LOWER(proxy_address)"
	if db.Name() == "mysql" {
		predicate = "BINARY domain <> BINARY LOWER(domain) OR BINARY proxy_address <> BINARY LOWER(proxy_address)"
	}
	res := db.Exec("UPDATE agent_network_settings SET domain = LOWER(domain), proxy_address = LOWER(proxy_address) WHERE " + predicate)
	if res.Error != nil {
		return fmt.Errorf("normalize agent_network_settings identity casing: %w", res.Error)
	}
	if res.RowsAffected > 0 {
		log.WithContext(ctx).Infof("normalized casing on %d agent_network_settings row(s)", res.RowsAffected)
	}

	return nil
}

// failOnDuplicateAgentNetworkDomains refuses to continue when two settings
// rows would fold onto one endpoint hostname. Two accounts cannot share an
// endpoint, the unique index would refuse the fold with a driver message that
// names no row, and there is no right answer as to which account keeps the
// name, so the migration stops and says which hostname needs a human.
func failOnDuplicateAgentNetworkDomains(db *gorm.DB) error {
	var rows []struct{ Domain string }
	err := db.Raw("SELECT LOWER(domain) AS domain FROM agent_network_settings GROUP BY LOWER(domain) HAVING COUNT(*) > 1").
		Scan(&rows).Error
	if err != nil {
		return fmt.Errorf("check agent_network_settings for endpoints differing only by case: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}
	duplicates := make([]string, 0, len(rows))
	for _, row := range rows {
		duplicates = append(duplicates, row.Domain)
	}
	return fmt.Errorf(
		"agent_network_settings holds endpoints that differ only by case (%s); resolve them manually before upgrading",
		strings.Join(duplicates, ", "),
	)
}
