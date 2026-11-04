package migration

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func MigrateNormalizeServiceDomains(ctx context.Context, db *gorm.DB) error {
	result := db.WithContext(ctx).Model(&rpservice.Service{}).
		Where("domain <> lower(domain)").
		Where("not exists (select 1 from services other where other.id <> services.id AND lower(other.domain) = lower(services.domain))").
		UpdateColumn("domain", gorm.Expr("lower(domain)"))
	if result.Error != nil {
		return fmt.Errorf("lowercase service domains: %w", result.Error)
	}

	var conflicting []string
	if err := db.WithContext(ctx).Model(&rpservice.Service{}).Where("domain <> lower(domain)").Pluck("domain", &conflicting).Error; err != nil {
		return fmt.Errorf("list conflicting service domains: %w", err)
	}
	if len(conflicting) > 0 {
		log.WithContext(ctx).Warnf("found service domains using the same domain name with different spelling: %v", conflicting)
	}
	return nil
}

func MigrateNormalizeProxyClusterDomains(ctx context.Context, db *gorm.DB) error {
	result := db.WithContext(ctx).Model(&proxy.Proxy{}).
		Where("cluster_address <> lower(cluster_address)").
		Where("not exists (select 1 from proxies other where other.id <> proxies.id AND lower(other.cluster_address) = lower(proxies.cluster_address))").
		UpdateColumn("cluster_address", gorm.Expr("lower(cluster_address)"))
	if result.Error != nil {
		return fmt.Errorf("lowercase proxy cluster address: %w", result.Error)
	}

	var conflicting []string
	if err := db.WithContext(ctx).Model(&proxy.Proxy{}).Where("cluster_address <> lower(cluster_address)").Pluck("cluster_address", &conflicting).Error; err != nil {
		return fmt.Errorf("list conflicting proxy cluster addresses: %w", err)
	}
	if len(conflicting) > 0 {
		log.WithContext(ctx).Warnf("found proxies using the same cluster address with different spelling: %v", conflicting)
	}
	return nil
}
