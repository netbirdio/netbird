package migration

import (
	"context"
	"fmt"

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
			// it (trimmed, never folded), while every path that reads these
			// columns now compares against canonical lowercase: proxy
			// addresses are canonicalised at connect and the proxy folds the
			// SNI host it routes on. Fold here so the reshaped row is
			// addressable, rather than copying a spelling nothing will match.
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

// NormalizeAgentNetworkSettingsIdentity lowercases domain and proxy_address
// on rows already reshaped by a release whose backfill copied the legacy
// cluster spelling verbatim.
//
// Both columns are compared exactly against canonical lowercase values: a
// proxy registering at a host asks whether another account's gateway is
// pinned there by proxy_address, cluster-scoped mapping synthesis finds the
// accounts a proxy serves the same way, and the proxy itself folds the SNI
// host before matching a mapping's domain. A row that kept capitals from the
// legacy schema is invisible to all three — its pin does not protect the
// host, and its endpoint is never matched — so the value is repaired where it
// is stored rather than folded on every read.
//
// Idempotent: the WHERE clause selects only rows that would change, so a
// normalised table costs one pass over a table holding one row per account.
// On MySQL the default collation already compares case-insensitively, so the
// predicate never matches there and the statement is a no-op, which is the
// right answer: nothing on MySQL was invisible to begin with. Runs after the
// reshape, so the columns exist whenever the table does. Two rows that differ
// only by case would collapse onto one domain, which the unique index
// refuses; that state is unreachable through the API and the migration fails
// loudly rather than guessing which endpoint to keep.
func NormalizeAgentNetworkSettingsIdentity(ctx context.Context, db *gorm.DB) error {
	model := &agentNetworkSettingsIdentity{}
	migrator := db.Migrator()

	if !migrator.HasTable(model) || !migrator.HasColumn(model, "Domain") || !migrator.HasColumn(model, "ProxyAddress") {
		return nil
	}

	res := db.Exec("UPDATE agent_network_settings SET domain = LOWER(domain), proxy_address = LOWER(proxy_address) " +
		"WHERE domain <> LOWER(domain) OR proxy_address <> LOWER(proxy_address)")
	if res.Error != nil {
		return fmt.Errorf("normalize agent_network_settings identity casing: %w", res.Error)
	}
	if res.RowsAffected > 0 {
		log.WithContext(ctx).Infof("normalized casing on %d agent_network_settings row(s)", res.RowsAffected)
	}

	return nil
}
