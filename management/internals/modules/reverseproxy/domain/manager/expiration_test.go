package manager

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbstore "github.com/netbirdio/netbird/management/server/store"
)

func TestValidateDomain_ExpiredRegistration(t *testing.T) {
	env := setupDomainTest(t)
	ctx := context.Background()
	d, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "expired.example.com", testCluster)
	require.NoError(t, err)
	expiresAt := time.Now().Add(-time.Second)
	db := env.store.(*nbstore.SqlStore).GetDB()
	require.NoError(t, db.Model(&domain.Domain{}).Where("id = ?", d.ID).
		Update("validation_expires_at", expiresAt).Error)
	env.resolver.set("validation.expired.example.com", testCluster)

	env.manager.ValidateDomain(ctx, accountA, accountAUser, d.ID)

	stored := storedDomain(t, env.store, accountA, d.Domain)
	require.NotNil(t, stored)
	assert.False(t, stored.Validated, "an expired registration must not become usable before cleanup runs")
}

func TestCreateDomain_ValidationDeadline(t *testing.T) {
	env := setupClockDomainTest(t)
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		createdAt := time.Now().UTC()
		d, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "pending.example.com", testCluster)
		require.NoError(t, err)
		require.NotNil(t, d.ValidationExpiresAt)
		assert.Equal(t, createdAt.Add(48*time.Hour), *d.ValidationExpiresAt, "new registrations get 48 hours")

		time.Sleep(time.Hour)
		env.manager.ValidateDomain(ctx, accountA, accountAUser, d.ID)
		stored := storedDomain(t, env.store, accountA, d.Domain)
		require.NotNil(t, stored)
		require.NotNil(t, stored.ValidationExpiresAt)
		assert.WithinDuration(t, *d.ValidationExpiresAt, *stored.ValidationExpiresAt, 0, "failed validation must not extend the deadline")
	})
}

func TestCleanupExpiredDomains_Boundaries(t *testing.T) {
	env := setupDomainTest(t)
	events := captureDomainEvents(env)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name      string
		expiresAt time.Time
		validated bool
		deleted   bool
	}{
		{"expired", now.Add(-time.Second), false, true},
		{"deadline", now, false, true},
		{"pending", now.Add(time.Second), false, false},
		{"validated", now.Add(-time.Hour), true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := createExpiringDomain(t, env, tt.name+".example.com", tt.expiresAt)
			if tt.validated {
				require.NoError(t, env.store.(*nbstore.SqlStore).GetDB().Model(d).Update("validated", true).Error)
			}
			env.manager.cleanupExpiredDomains(ctx, now)
			stored := storedDomain(t, env.store, accountA, d.Domain)
			if !tt.deleted {
				assert.NotNil(t, stored, "pending and validated registrations must survive cleanup")
				return
			}
			assert.Nil(t, stored, "expired unused registrations must be removed")
			replacement, err := env.manager.CreateDomain(ctx, accountB, accountBUser, d.Domain, testCluster)
			require.NoError(t, err)
			assert.NotEqual(t, d.ID, replacement.ID, "the released name must receive a fresh registration")
			assert.False(t, replacement.Validated, "the new account must validate its own registration")
		})
	}
	got := events.get()
	require.Len(t, got, 2, "only successful expiration deletions emit events")
	for _, event := range got {
		assert.Equal(t, activity.CustomDomainValidationExpired, event.Activity, "use the requested expiration event")
		assert.Equal(t, activity.SystemInitiator, event.InitiatorID, "cleanup is attributed to the system")
		assert.Equal(t, accountA, event.AccountID, "expiration belongs to the original account")
		assert.NotEmpty(t, event.TargetID, "retain the deleted domain ID")
		assert.NotEmpty(t, event.Meta["domain"], "retain the deleted domain name")
		assert.NotEmpty(t, event.Meta["validation_expires_at"], "include the validation deadline")
	}
}

func TestCleanupExpiredDomains_ContinuesPastProtectedBatch(t *testing.T) {
	env := setupDomainTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := range validationCleanupBatch {
		d := createExpiringDomain(t, env, fmt.Sprintf("protected-%d.example.com", i), now.Add(-time.Hour))
		require.NoError(t, env.store.CreateService(ctx, &rpservice.Service{
			ID: fmt.Sprintf("service-%d", i), AccountID: accountA, Domain: "app." + d.Domain,
		}))
	}
	unprotected := createExpiringDomain(t, env, "unused.example.com", now.Add(-time.Hour))
	env.manager.cleanupExpiredDomains(ctx, now)
	assert.Nil(t, storedDomain(t, env.store, accountA, unprotected.Domain), "protected registrations must not starve later batches")
	remaining, err := env.store.ListCustomDomains(ctx, accountA)
	require.NoError(t, err)
	assert.Len(t, remaining, validationCleanupBatch, "all registrations with dependent services must survive")
}

func TestCleanupExpiredDomains_ConcurrentWorkers(t *testing.T) {
	env := setupDomainTest(t)
	events := captureDomainEvents(env)
	now := time.Now().UTC()
	d := createExpiringDomain(t, env, "concurrent.example.com", now.Add(-time.Hour))
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() { env.manager.cleanupExpiredDomains(context.Background(), now) })
	}
	workers.Wait()
	assert.Nil(t, storedDomain(t, env.store, accountA, d.Domain), "one worker must remove the expired registration")
	assert.Len(t, events.get(), 1, "only the worker that deletes the row may emit the event")
}

func TestRunValidationCleanup_HourlyAndRestart(t *testing.T) {
	env := setupClockDomainTest(t)
	synctest.Test(t, func(t *testing.T) {
		events := captureDomainEvents(env)
		now := time.Now().UTC()
		startup := createExpiringDomain(t, env, "startup.example.com", now.Add(-time.Hour))
		hourly := createExpiringDomain(t, env, "hourly.example.com", now.Add(time.Minute))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			env.manager.RunValidationCleanup(ctx)
		}()
		synctest.Wait()
		assert.Nil(t, storedDomain(t, env.store, accountA, startup.Domain), "startup must collect overdue registrations")
		time.Sleep(59 * time.Minute)
		synctest.Wait()
		assert.NotNil(t, storedDomain(t, env.store, accountA, hourly.Domain), "cleanup must wait for the 60-minute interval")
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Nil(t, storedDomain(t, env.store, accountA, hourly.Domain), "the hourly scan must collect expired registrations")
		cancel()
		<-done

		offline := createExpiringDomain(t, env, "offline.example.com", time.Now().UTC().Add(time.Minute))
		time.Sleep(2 * time.Hour)
		assert.NotNil(t, storedDomain(t, env.store, accountA, offline.Domain), "a stopped worker must not continue deleting")
		ctx, cancel = context.WithCancel(context.Background())
		done = make(chan struct{})
		go func() {
			defer close(done)
			env.manager.RunValidationCleanup(ctx)
		}()
		synctest.Wait()
		assert.Nil(t, storedDomain(t, env.store, accountA, offline.Domain), "restart must use the persisted deadline")
		cancel()
		<-done
		assert.Len(t, events.get(), 3, "each deletion should emit an expiration event")
	})
}

type blockingDomainResolver struct {
	started chan struct{}
	release chan struct{}
}

func (r blockingDomainResolver) LookupCNAME(context.Context, string) (string, error) {
	close(r.started)
	<-r.release
	return testCluster + ".", nil
}

func TestValidateDomain_DeadlinePassesDuringLookup(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup=%t", cleanup), func(t *testing.T) {
			env := setupClockDomainTest(t)
			synctest.Test(t, func(t *testing.T) {
				events := captureDomainEvents(env)
				ctx := context.Background()
				d, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "late.example.com", testCluster)
				require.NoError(t, err)
				resolver := blockingDomainResolver{started: make(chan struct{}), release: make(chan struct{})}
				env.manager.validator.Resolver = resolver
				done := make(chan struct{})
				go func() {
					defer close(done)
					env.manager.ValidateDomain(ctx, accountA, accountAUser, d.ID)
				}()
				<-resolver.started
				time.Sleep(48 * time.Hour)
				if cleanup {
					env.manager.cleanupExpiredDomains(ctx, time.Now().UTC())
					_, err = env.store.CreateCustomDomain(ctx, accountB, d.Domain, testCluster, false)
					require.NoError(t, err)
				}
				close(resolver.release)
				<-done
				owner := accountA
				if cleanup {
					assert.Nil(t, storedDomain(t, env.store, accountA, d.Domain), "late validation must not restore the old claim")
					owner = accountB
				}
				stored := storedDomain(t, env.store, owner, d.Domain)
				require.NotNil(t, stored)
				assert.False(t, stored.Validated, "late validation must not validate either claim")
				for _, event := range events.get() {
					assert.NotEqual(t, activity.DomainValidated, event.Activity, "a rejected write must not emit a validation event")
				}
			})
		})
	}
}

func setupClockDomainTest(t *testing.T) *domainTestEnv {
	t.Helper()
	// Network driver watchers cannot share cancellation channels across synctest bubbles.
	// Store boundary and concurrency tests still exercise the selected database engine.
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	return setupDomainTest(t)
}

func createExpiringDomain(t *testing.T, env *domainTestEnv, name string, expiresAt time.Time) *domain.Domain {
	t.Helper()
	d, err := env.store.CreateCustomDomain(context.Background(), accountA, name, testCluster, false)
	require.NoError(t, err)
	require.NoError(t, env.store.(*nbstore.SqlStore).GetDB().Model(d).Update("validation_expires_at", expiresAt).Error)
	d.ValidationExpiresAt = &expiresAt
	return d
}

type domainEvents struct {
	mu     sync.Mutex
	events []*activity.Event
}

func captureDomainEvents(env *domainTestEnv) *domainEvents {
	events := &domainEvents{}
	env.manager.accountManager = &mock_server.MockAccountManager{
		StoreEventFunc: func(_ context.Context, initiator, target, account string, code activity.ActivityDescriber, meta map[string]any) {
			if code == activity.DomainAdded {
				return
			}
			events.mu.Lock()
			defer events.mu.Unlock()
			events.events = append(events.events, &activity.Event{
				InitiatorID: initiator, TargetID: target, AccountID: account,
				Activity: code.(activity.Activity), Meta: meta,
			})
		},
	}
	return events
}

func (e *domainEvents) get() []*activity.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*activity.Event(nil), e.events...)
}
