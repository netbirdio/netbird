package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestDeleteCustomDomain_ServiceDependencies(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		require.NoError(t, store.SaveAccount(ctx, newAccountWithId(ctx, "owner", "admin", "")))
		d, err := store.CreateCustomDomain(ctx, "owner", "example.com", "cluster", true)
		require.NoError(t, err)
		svc := &rpservice.Service{ID: "service", AccountID: "owner", Domain: "APP.EXAMPLE.COM."}
		require.NoError(t, store.CreateService(ctx, svc))

		err = store.DeleteCustomDomain(ctx, "other", d.ID)
		require.Error(t, err)
		sErr, ok := status.FromError(err)
		require.True(t, ok, "cross-account deletion must return a typed error")
		assert.Equal(t, status.NotFound, sErr.Type(), "cross-account deletion must not reveal dependencies")

		err = store.DeleteCustomDomain(ctx, "owner", d.ID)
		require.Error(t, err)
		sErr, ok = status.FromError(err)
		require.True(t, ok, "dependent services must return a typed error")
		assert.Equal(t, status.PreconditionFailed, sErr.Type(), "deletion must fail until services are removed")
		stored, err := store.GetCustomDomain(ctx, "owner", d.ID)
		require.NoError(t, err)
		assert.True(t, stored.Validated, "rejected deletion must preserve validation")

		require.NoError(t, store.DeleteService(ctx, "owner", svc.ID))
		require.NoError(t, store.DeleteCustomDomain(ctx, "owner", d.ID))
		_, err = store.GetCustomDomain(ctx, "owner", d.ID)
		require.Error(t, err, "the registration must be gone after successful deletion")
	})
}

func TestDeleteCustomDomain_ConcurrentServiceCreation(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		require.NoError(t, store.SaveAccount(ctx, newAccountWithId(ctx, "owner", "admin", "")))
		for i := range 10 {
			d, err := store.CreateCustomDomain(ctx, "owner", fmt.Sprintf("app%d.example.com", i), "cluster", true)
			require.NoError(t, err)
			svc := &rpservice.Service{ID: fmt.Sprintf("service-%d", i), AccountID: "owner", Domain: d.Domain}
			start := make(chan struct{})
			created := make(chan error, 1)
			deleted := make(chan error, 1)
			go func() {
				<-start
				created <- store.ExecuteInTransaction(ctx, func(tx Store) error {
					domains, err := tx.LockCustomDomains(ctx, "owner")
					if err != nil {
						return err
					}
					for _, candidate := range domains {
						if candidate.ID == d.ID && candidate.Validated {
							return tx.CreateService(ctx, svc)
						}
					}
					return status.Errorf(status.PreconditionFailed, "registration was deleted")
				})
			}()
			go func() {
				<-start
				deleted <- store.DeleteCustomDomain(ctx, "owner", d.ID)
			}()
			close(start)
			createErr, deleteErr := <-created, <-deleted
			require.True(t, createErr == nil || deleteErr == nil, "one operation must succeed: create=%v, delete=%v", createErr, deleteErr)
			if createErr == nil {
				require.Error(t, deleteErr, "a committed service must block deletion")
				stored, err := store.GetCustomDomain(ctx, "owner", d.ID)
				require.NoError(t, err)
				assert.True(t, stored.Validated, "the service must retain its authorization")
				require.NoError(t, store.DeleteService(ctx, "owner", svc.ID))
				require.NoError(t, store.DeleteCustomDomain(ctx, "owner", d.ID))
				continue
			}
			require.NoError(t, deleteErr)
			services, err := store.GetAccountServices(ctx, LockingStrengthNone, "owner")
			require.NoError(t, err)
			assert.Empty(t, services, "a deleted registration must not leave a new service")
		}
	})
}
