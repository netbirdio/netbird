package migration_test

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/migration"
)

type legacySharedDomainService struct {
	ID     string `gorm:"primaryKey"`
	Domain string `gorm:"type:varchar(255);uniqueIndex"`
	Mode   string `gorm:"default:'http'"`
}

type earliestSharedDomainService struct {
	ID     string `gorm:"primaryKey"`
	Domain string `gorm:"type:varchar(255);uniqueIndex"`
}

func (earliestSharedDomainService) TableName() string {
	return "services"
}

type legacyTLSSharedDomainService struct {
	ID           string `gorm:"primaryKey"`
	AccountID    string
	Domain       string `gorm:"type:varchar(255);uniqueIndex"`
	Mode         string
	ProxyCluster string
	ListenPort   uint16
}

func (legacyTLSSharedDomainService) TableName() string {
	return "services"
}

func (legacySharedDomainService) TableName() string {
	return "services"
}

func TestMigrateReverseProxySharedDomains(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	db := setupDatabase(t)
	require.NoError(t, db.Migrator().DropTable(&rpservice.Service{}))
	require.NoError(t, db.AutoMigrate(&legacySharedDomainService{}))

	legacy := []*legacySharedDomainService{
		{ID: "http", Domain: " Web.Example. ", Mode: rpservice.ModeHTTP},
		{ID: "tcp", Domain: "WEB.EXAMPLE", Mode: rpservice.ModeTCP},
		{ID: "udp", Domain: "web.example.", Mode: rpservice.ModeUDP},
	}
	for _, service := range legacy {
		require.NoError(t, db.Create(service).Error)
	}

	ctx := context.Background()
	require.NoError(t, migration.PrepareReverseProxySharedDomains(ctx, db))
	assert.False(t, db.Migrator().HasIndex(&legacySharedDomainService{}, "idx_services_domain"))

	require.NoError(t, db.AutoMigrate(&rpservice.Service{}))
	require.NoError(t, migration.BackfillReverseProxyHTTPDomains(ctx, db))

	var migrated []*rpservice.Service
	require.NoError(t, db.Order("id ASC").Find(&migrated).Error)
	require.Len(t, migrated, 3)
	for _, service := range migrated {
		assert.Equal(t, "web.example", service.Domain)
		if service.Mode == rpservice.ModeHTTP {
			require.NotNil(t, service.HTTPDomain)
			assert.Equal(t, service.Domain, *service.HTTPDomain)
		} else {
			assert.Nil(t, service.HTTPDomain)
		}
	}
	assert.True(t, db.Migrator().HasIndex(&rpservice.Service{}, "idx_services_domain_lookup"))
	assert.True(t, db.Migrator().HasIndex(&rpservice.Service{}, "idx_services_http_domain"))

	extraL4 := &rpservice.Service{ID: "tcp-2", Domain: "WEB.EXAMPLE.", Mode: rpservice.ModeTCP}
	require.NoError(t, extraL4.CanonicalizeDomain())
	require.NoError(t, db.Create(extraL4).Error)

	duplicateHTTP := &rpservice.Service{ID: "http-2", Domain: "WEB.EXAMPLE.", Mode: rpservice.ModeHTTP}
	require.NoError(t, duplicateHTTP.CanonicalizeDomain())
	require.Error(t, db.Create(duplicateHTTP).Error)

	// Both phases are safe to run on every startup.
	require.NoError(t, migration.PrepareReverseProxySharedDomains(ctx, db))
	require.NoError(t, migration.BackfillReverseProxyHTTPDomains(ctx, db))
}

func TestPrepareReverseProxySharedDomainsDirectUpgradeWithoutModeOrListenPort(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	db := setupDatabase(t)
	require.NoError(t, db.Migrator().DropTable(&rpservice.Service{}))
	require.NoError(t, db.AutoMigrate(&earliestSharedDomainService{}))
	require.NoError(t, db.Create(&earliestSharedDomainService{ID: "http", Domain: " OLD.Example. "}).Error)

	ctx := context.Background()
	require.NoError(t, migration.PrepareReverseProxySharedDomains(ctx, db))
	assert.False(t, db.Migrator().HasIndex(&earliestSharedDomainService{}, "idx_services_domain"))

	var domain string
	require.NoError(t, db.Model(&earliestSharedDomainService{}).Where("id = ?", "http").Pluck("domain", &domain).Error)
	assert.Equal(t, "old.example", domain)

	// AutoMigrate can now add the modern mode/listener/ownership columns and
	// the HTTP ownership backfill treats a missing legacy mode as HTTP.
	require.NoError(t, db.AutoMigrate(&rpservice.Service{}, &rpservice.PortMapping{}, &rpservice.DomainLock{}))
	require.NoError(t, migration.BackfillReverseProxyHTTPDomains(ctx, db))
	var migrated rpservice.Service
	require.NoError(t, db.Where("id = ?", "http").First(&migrated).Error)
	require.NotNil(t, migrated.HTTPDomain)
	assert.Equal(t, "old.example", *migrated.HTTPDomain)
}

func TestPrepareReverseProxySharedDomainsRejectsCanonicalHTTPDuplicates(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	db := setupDatabase(t)
	require.NoError(t, db.Migrator().DropTable(&rpservice.Service{}))
	require.NoError(t, db.AutoMigrate(&legacySharedDomainService{}))

	require.NoError(t, db.Create(&legacySharedDomainService{ID: "http-1", Domain: "App.Example", Mode: rpservice.ModeHTTP}).Error)
	require.NoError(t, db.Create(&legacySharedDomainService{ID: "http-2", Domain: "app.example.", Mode: rpservice.ModeHTTP}).Error)

	err := migration.PrepareReverseProxySharedDomains(context.Background(), db)
	require.ErrorContains(t, err, "multiple HTTP services")
	assert.True(t, db.Migrator().HasIndex(&legacySharedDomainService{}, "idx_services_domain"), "legacy safety index must remain when validation fails")

	var domains []string
	require.NoError(t, db.Model(&legacySharedDomainService{}).Order("id ASC").Pluck("domain", &domains).Error)
	assert.Equal(t, []string{"App.Example", "app.example."}, domains)
}

func TestPrepareReverseProxySharedDomainsRejectsCanonicalHTTPAndTLS(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	db := setupDatabase(t)
	require.NoError(t, db.Migrator().DropTable(&rpservice.Service{}))
	require.NoError(t, db.AutoMigrate(&legacySharedDomainService{}))

	require.NoError(t, db.Create(&legacySharedDomainService{ID: "http", Domain: "App.Example", Mode: rpservice.ModeHTTP}).Error)
	require.NoError(t, db.Create(&legacySharedDomainService{ID: "tls", Domain: "app.example.", Mode: rpservice.ModeTLS}).Error)

	err := migration.PrepareReverseProxySharedDomains(context.Background(), db)
	require.ErrorContains(t, err, "HTTP service http and TLS passthrough service tls")
	assert.True(t, db.Migrator().HasIndex(&legacySharedDomainService{}, "idx_services_domain"), "legacy safety index must remain when validation fails")
}

func TestPrepareReverseProxySharedDomainsRejectsMappedTLSCollision(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	db := setupDatabase(t)
	require.NoError(t, db.Migrator().DropTable(&rpservice.PortMapping{}, &rpservice.Service{}))
	require.NoError(t, db.AutoMigrate(&legacySharedDomainService{}, &rpservice.PortMapping{}))

	require.NoError(t, db.Create(&legacySharedDomainService{ID: "http", Domain: "App.Example", Mode: rpservice.ModeHTTP}).Error)
	require.NoError(t, db.Create(&legacySharedDomainService{ID: "mapped", Domain: "app.example.", Mode: rpservice.ModeTCP}).Error)
	require.NoError(t, db.Create(&rpservice.PortMapping{
		AccountID: "account-1", ServiceID: "mapped", Protocol: rpservice.ModeTLS,
		ListenPortStart: 8443, ListenPortEnd: 8443, TargetPortStart: 9443, TargetPortEnd: 9443,
	}).Error)

	err := migration.PrepareReverseProxySharedDomains(context.Background(), db)
	require.ErrorContains(t, err, "HTTP service http and TLS passthrough service mapped")
	assert.True(t, db.Migrator().HasIndex(&legacySharedDomainService{}, "idx_services_domain"))
}

func TestPrepareReverseProxySharedDomainsRejectsCanonicalLegacyTLSAliasCollision(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	db := setupDatabase(t)
	require.NoError(t, db.Migrator().DropTable(&rpservice.PortMapping{}, &rpservice.Service{}))
	require.NoError(t, db.AutoMigrate(&legacyTLSSharedDomainService{}))

	require.NoError(t, db.Create(&legacyTLSSharedDomainService{
		ID: "tls-1", AccountID: "account-1", Domain: "TLS.Example", Mode: rpservice.ModeTLS,
		ProxyCluster: "cluster.example", ListenPort: 443,
	}).Error)
	require.NoError(t, db.Create(&legacyTLSSharedDomainService{
		ID: "tls-2", AccountID: "account-1", Domain: "tls.example.", Mode: rpservice.ModeTLS,
		ProxyCluster: "cluster.example", ListenPort: 443,
	}).Error)

	err := migration.PrepareReverseProxySharedDomains(context.Background(), db)
	require.ErrorContains(t, err, "overlapping TLS passthrough listeners")
	assert.True(t, db.Migrator().HasIndex(&legacyTLSSharedDomainService{}, "idx_services_domain"))
}

func TestPrepareReverseProxySharedDomainsRejectsCanonicalMappedTLSRangeCollision(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	db := setupDatabase(t)
	require.NoError(t, db.Migrator().DropTable(&rpservice.PortMapping{}, &rpservice.Service{}))
	require.NoError(t, db.AutoMigrate(&legacyTLSSharedDomainService{}, &rpservice.PortMapping{}))

	for _, svc := range []*legacyTLSSharedDomainService{
		{ID: "tls-1", AccountID: "account-1", Domain: "TLS.Example", Mode: rpservice.ModeTCP, ProxyCluster: "cluster.example"},
		{ID: "tls-2", AccountID: "account-1", Domain: "tls.example.", Mode: rpservice.ModeTCP, ProxyCluster: "cluster.example"},
	} {
		require.NoError(t, db.Create(svc).Error)
	}
	for _, mapping := range []*rpservice.PortMapping{
		{AccountID: "account-1", ServiceID: "tls-1", Protocol: rpservice.ModeTLS, ListenPortStart: 8000, ListenPortEnd: 8010, TargetPortStart: 8000, TargetPortEnd: 8010},
		{AccountID: "account-1", ServiceID: "tls-2", Protocol: rpservice.ModeTLS, ListenPortStart: 8010, ListenPortEnd: 8020, TargetPortStart: 8010, TargetPortEnd: 8020},
	} {
		require.NoError(t, db.Create(mapping).Error)
	}

	err := migration.PrepareReverseProxySharedDomains(context.Background(), db)
	require.ErrorContains(t, err, "overlapping TLS passthrough listeners")
	assert.True(t, db.Migrator().HasIndex(&legacyTLSSharedDomainService{}, "idx_services_domain"))
}

func TestPrepareReverseProxySharedDomainsRejectsCrossAccountCanonicalAlias(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	db := setupDatabase(t)
	require.NoError(t, db.Migrator().DropTable(&rpservice.Service{}))
	require.NoError(t, db.AutoMigrate(&legacyTLSSharedDomainService{}))

	require.NoError(t, db.Create(&legacyTLSSharedDomainService{ID: "one", AccountID: "account-1", Domain: "Shared.Example", Mode: rpservice.ModeTCP}).Error)
	require.NoError(t, db.Create(&legacyTLSSharedDomainService{ID: "two", AccountID: "account-2", Domain: "shared.example.", Mode: rpservice.ModeUDP}).Error)

	err := migration.PrepareReverseProxySharedDomains(context.Background(), db)
	require.ErrorContains(t, err, "owned by multiple accounts")
	assert.True(t, db.Migrator().HasIndex(&legacyTLSSharedDomainService{}, "idx_services_domain"))
}

func TestReverseProxySharedDomainMigrationCrossDatabase(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip container-backed migration tests on darwin and windows CI")
	}

	for _, engine := range []string{"postgres", "mysql"} {
		t.Run(engine, func(t *testing.T) {
			t.Setenv("NETBIRD_STORE_ENGINE", engine)
			db := setupDatabase(t)
			ctx := context.Background()

			resetSchema := func(t *testing.T) {
				t.Helper()
				require.NoError(t, db.Migrator().DropTable(
					&rpservice.PortMapping{},
					&rpservice.Target{},
					&rpservice.DomainLock{},
					&rpservice.Service{},
				))
			}

			t.Run("positive legacy upgrade", func(t *testing.T) {
				resetSchema(t)
				require.NoError(t, db.AutoMigrate(&legacySharedDomainService{}))

				for _, service := range []*legacySharedDomainService{
					{ID: "http", Domain: " Web.Example. ", Mode: rpservice.ModeHTTP},
					{ID: "tcp", Domain: "WEB.EXAMPLE", Mode: rpservice.ModeTCP},
					{ID: "udp", Domain: "web.example.", Mode: rpservice.ModeUDP},
				} {
					require.NoError(t, db.Create(service).Error)
				}

				require.NoError(t, migration.PrepareReverseProxySharedDomains(ctx, db))
				assert.False(t, db.Migrator().HasIndex(&legacySharedDomainService{}, "idx_services_domain"))
				require.NoError(t, db.AutoMigrate(&rpservice.Service{}, &rpservice.PortMapping{}, &rpservice.DomainLock{}))
				require.NoError(t, migration.BackfillReverseProxyHTTPDomains(ctx, db))

				var migrated []*rpservice.Service
				require.NoError(t, db.Order("id ASC").Find(&migrated).Error)
				require.Len(t, migrated, 3)
				for _, service := range migrated {
					assert.Equal(t, "web.example", service.Domain)
					if service.Mode == rpservice.ModeHTTP {
						require.NotNil(t, service.HTTPDomain)
						assert.Equal(t, "web.example", *service.HTTPDomain)
					} else {
						assert.Nil(t, service.HTTPDomain)
					}
				}
				assert.True(t, db.Migrator().HasIndex(&rpservice.Service{}, "idx_services_domain_lookup"))
				assert.True(t, db.Migrator().HasIndex(&rpservice.Service{}, "idx_services_http_domain"))
			})

			t.Run("earliest schema without mode or listener", func(t *testing.T) {
				resetSchema(t)
				require.NoError(t, db.AutoMigrate(&earliestSharedDomainService{}))
				require.NoError(t, db.Create(&earliestSharedDomainService{ID: "http", Domain: " OLD.Example. "}).Error)

				require.NoError(t, migration.PrepareReverseProxySharedDomains(ctx, db))
				assert.False(t, db.Migrator().HasIndex(&earliestSharedDomainService{}, "idx_services_domain"))
				require.NoError(t, db.AutoMigrate(&rpservice.Service{}, &rpservice.PortMapping{}, &rpservice.DomainLock{}))
				require.NoError(t, migration.BackfillReverseProxyHTTPDomains(ctx, db))

				var migrated rpservice.Service
				require.NoError(t, db.Where("id = ?", "http").First(&migrated).Error)
				assert.Equal(t, "old.example", migrated.Domain)
				require.NotNil(t, migrated.HTTPDomain)
				assert.Equal(t, "old.example", *migrated.HTTPDomain)
			})

			t.Run("collision rejection is pre mutation", func(t *testing.T) {
				resetSchema(t)
				require.NoError(t, db.AutoMigrate(&legacySharedDomainService{}))
				require.NoError(t, db.Create(&legacySharedDomainService{ID: "http-1", Domain: "App.Example", Mode: rpservice.ModeHTTP}).Error)
				require.NoError(t, db.Create(&legacySharedDomainService{ID: "http-2", Domain: "app.example.", Mode: rpservice.ModeHTTP}).Error)

				err := migration.PrepareReverseProxySharedDomains(ctx, db)
				require.ErrorContains(t, err, "multiple HTTP services")
				assert.True(t, db.Migrator().HasIndex(&legacySharedDomainService{}, "idx_services_domain"))

				var domains []string
				require.NoError(t, db.Model(&legacySharedDomainService{}).Order("id ASC").Pluck("domain", &domains).Error)
				assert.Equal(t, []string{"App.Example", "app.example."}, domains)
			})
		})
	}
}
