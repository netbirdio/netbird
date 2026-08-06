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
func MigrateAgentNetworkSettingsToDomain(ctx context.Context, db *gorm.DB) error {
	model := &agentNetworkSettingsMigration{}
	migrator := db.Migrator()

	if !migrator.HasTable(model) {
		return nil
	}
	if !migrator.HasColumn(model, "cluster") {
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

		concat := "subdomain || '.' || cluster"
		if tx.Name() == "mysql" {
			concat = "CONCAT(subdomain, '.', cluster)"
		}
		res := tx.Exec(fmt.Sprintf(
			"UPDATE agent_network_settings SET domain = %s, proxy_address = cluster WHERE (domain IS NULL OR domain = '') AND cluster <> '' AND subdomain <> ''",
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

		if txMigrator.HasIndex(model, "idx_agent_network_settings_cluster_subdomain") {
			if err := txMigrator.DropIndex(model, "idx_agent_network_settings_cluster_subdomain"); err != nil {
				return fmt.Errorf("drop legacy agent_network_settings index: %w", err)
			}
		}
		for _, field := range []string{"Cluster", "Subdomain"} {
			if err := txMigrator.DropColumn(model, field); err != nil {
				return fmt.Errorf("drop legacy agent_network_settings column %s: %w", field, err)
			}
		}

		if res.RowsAffected > 0 {
			log.WithContext(ctx).Infof("migrated %d agent_network_settings row(s) to domain/proxy_address", res.RowsAffected)
		}
		return nil
	})
}
