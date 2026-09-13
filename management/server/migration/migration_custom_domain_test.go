package migration_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	"github.com/netbirdio/netbird/management/server/migration"
)

func TestMigrateCustomDomainValidationExpiry(t *testing.T) {
	db := setupDatabase(t)
	require.NoError(t, db.AutoMigrate(&domain.Domain{}))
	t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(&domain.Domain{})) })
	ctx := context.Background()
	existingDeadline := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	rows := []domain.Domain{
		{ID: "legacy", Domain: "legacy.example.com"},
		{ID: "validated", Domain: "validated.example.com", Validated: true},
		{ID: "pending", Domain: "pending.example.com", ValidationExpiresAt: &existingDeadline},
	}
	require.NoError(t, db.Create(&rows).Error)
	before := time.Now().UTC()
	require.NoError(t, migration.MigrateCustomDomainValidationExpiry(ctx, db))
	after := time.Now().UTC()
	var migrated domain.Domain
	require.NoError(t, db.First(&migrated, "id = ?", "legacy").Error)
	require.NotNil(t, migrated.ValidationExpiresAt)
	assert.WithinRange(t, *migrated.ValidationExpiresAt, before.Truncate(time.Millisecond).Add(48*time.Hour), after.Add(48*time.Hour+time.Millisecond), "legacy pending registrations get a full window")
	deadline := *migrated.ValidationExpiresAt
	require.NoError(t, migration.MigrateCustomDomainValidationExpiry(ctx, db))
	require.NoError(t, db.First(&migrated, "id = ?", "legacy").Error)
	assert.Equal(t, deadline, *migrated.ValidationExpiresAt, "repeated migration must not extend the deadline")
	var validated, pending domain.Domain
	require.NoError(t, db.First(&validated, "id = ?", "validated").Error)
	require.NoError(t, db.First(&pending, "id = ?", "pending").Error)
	assert.Nil(t, validated.ValidationExpiresAt, "validated domains do not acquire an expiry")
	require.NotNil(t, pending.ValidationExpiresAt)
	assert.WithinDuration(t, existingDeadline, *pending.ValidationExpiresAt, 0, "existing deadlines must be preserved")
}
