package migration

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
)

// MigrateReverseProxyPortMappings backfills the additive child table from the
// legacy scalar L4 fields. The original fields and target rows are intentionally
// retained, making downgrades non-destructive: older binaries ignore the new
// table and continue to see their original one-port representation.
func MigrateReverseProxyPortMappings(ctx context.Context, db *gorm.DB) error {
	if !db.Migrator().HasTable(&rpservice.Service{}) ||
		!db.Migrator().HasTable(&rpservice.Target{}) ||
		!db.Migrator().HasTable(&rpservice.PortMapping{}) {
		log.WithContext(ctx).Debug("reverse-proxy port mapping tables are incomplete, no migration needed")
		return nil
	}

	var services []*rpservice.Service
	if err := db.
		Preload("Targets", func(tx *gorm.DB) *gorm.DB { return tx.Order("id ASC") }).
		Where("mode IN ?", []string{rpservice.ModeTCP, rpservice.ModeUDP, rpservice.ModeTLS}).
		Find(&services).Error; err != nil {
		return fmt.Errorf("load legacy reverse-proxy services: %w", err)
	}

	var migrated int
	err := db.Transaction(func(tx *gorm.DB) error {
		for _, service := range services {
			var count int64
			if err := tx.Model(&rpservice.PortMapping{}).
				Where("service_id = ?", service.ID).
				Count(&count).Error; err != nil {
				return fmt.Errorf("count mappings for service %s: %w", service.ID, err)
			}
			if count > 0 {
				continue
			}
			if service.ListenPort == 0 || len(service.Targets) == 0 || service.Targets[0].Port == 0 {
				log.WithContext(ctx).Warnf(
					"skipping invalid legacy reverse-proxy service %s during port-mapping migration: mode=%s listen_port=%d targets=%d",
					service.ID,
					service.Mode,
					service.ListenPort,
					len(service.Targets),
				)
				continue
			}

			mapping := &rpservice.PortMapping{
				AccountID:       service.AccountID,
				ServiceID:       service.ID,
				Protocol:        service.Mode,
				ListenPortStart: service.ListenPort,
				ListenPortEnd:   service.ListenPort,
				TargetPortStart: service.Targets[0].Port,
				TargetPortEnd:   service.Targets[0].Port,
				Position:        0,
			}
			if err := tx.Create(mapping).Error; err != nil {
				return fmt.Errorf("backfill mapping for service %s: %w", service.ID, err)
			}
			migrated++
		}
		return nil
	})
	if err != nil {
		return err
	}

	if migrated > 0 {
		log.WithContext(ctx).Infof("migrated %d legacy reverse-proxy service(s) to port mappings", migrated)
	}
	return nil
}
