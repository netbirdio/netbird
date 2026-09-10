package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
)

func TestDeleteExpiredCustomDomain_ServiceDependencies(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		now := time.Now().UTC()
		db := store.(*SqlStore).db
		require.NoError(t, store.SaveAccount(ctx, newAccountWithId(ctx, "owner", "admin", "")))
		for _, tt := range []struct {
			name        string
			serviceHost string
			protected   bool
		}{
			{"exact", "example.com", true},
			{"subdomain", "deep.app.example.com", true},
			{"case", "APP.EXAMPLE.COM.", true},
			{"suffix-boundary", "notexample.com", false},
		} {
			t.Run(tt.name, func(t *testing.T) {
				d, err := store.CreateCustomDomain(ctx, "owner", "example.com", "cluster", false)
				require.NoError(t, err)
				require.NoError(t, db.Model(d).Update("validation_expires_at", now.Add(-time.Hour)).Error)
				svc := &rpservice.Service{ID: "legacy", AccountID: "owner", Domain: tt.serviceHost}
				require.NoError(t, store.CreateService(ctx, svc))
				deleted, err := store.DeleteExpiredCustomDomain(ctx, d, now)
				if tt.protected {
					require.Error(t, err)
					assert.False(t, deleted, "service namespaces must remain reserved")
				} else {
					require.NoError(t, err)
					assert.True(t, deleted, "a hostname outside the namespace must not prevent cleanup")
				}
				require.NoError(t, db.Delete(svc).Error)
				require.NoError(t, db.Delete(d).Error)
			})
		}
	})
}

func TestDeleteExpiredCustomDomain_RechecksValidation(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		require.NoError(t, store.SaveAccount(ctx, newAccountWithId(ctx, "owner", "admin", "")))
		d, err := store.CreateCustomDomain(ctx, "owner", "validated.example.com", "cluster", false)
		require.NoError(t, err)
		d, err = store.GetCustomDomain(ctx, "owner", d.ID)
		require.NoError(t, err)
		stale := d.Copy()
		d.Validated = true
		_, err = store.UpdateCustomDomain(ctx, "owner", d)
		require.NoError(t, err)
		deleted, err := store.DeleteExpiredCustomDomain(ctx, stale, time.Now().Add(domain.ValidationTTL))
		require.NoError(t, err)
		assert.False(t, deleted, "a stale cleanup candidate must not delete a validated registration")
		stored, err := store.GetCustomDomain(ctx, "owner", d.ID)
		require.NoError(t, err)
		assert.True(t, stored.Validated, "the validated registration must remain usable")
		require.NotNil(t, stored.ValidationExpiresAt)
		assert.Equal(t, stale.ValidationExpiresAt, stored.ValidationExpiresAt, "validation must preserve the original deadline")
	})
}
