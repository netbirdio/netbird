package manager

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	nbstore "github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// The validator tests cover each DNS outcome. These cover what the manager adds on top:
// the status type the API turns into a response code, and the checks before the lookup.
func TestValidateDomain_ReturnsReason(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		setup   func(t *testing.T, env *domainTestEnv, d *domain.Domain)
		user    string
		want    status.Type
		message string
	}{
		{
			name: "cname mismatch",
			setup: func(_ *testing.T, env *domainTestEnv, d *domain.Domain) {
				env.resolver.set("validation."+d.Domain, "other.example.net")
			},
			want:    status.PreconditionFailed,
			message: "CNAME record validation.test.example.com points to other.example.net; point it to " + testCluster,
		},
		{
			name: "expired window",
			setup: func(t *testing.T, env *domainTestEnv, d *domain.Domain) {
				setDomainColumn(t, env, d, "validation_expires_at", time.Now().Add(-time.Second))
			},
			want:    status.PreconditionFailed,
			message: "custom domain test.example.com validation window has expired; delete and add the domain again",
		},
		{
			name: "no target cluster",
			setup: func(t *testing.T, env *domainTestEnv, d *domain.Domain) {
				setDomainColumn(t, env, d, "target_cluster", "")
			},
			want:    status.PreconditionFailed,
			message: "custom domain test.example.com has no target cluster",
		},
		{
			name: "permission denied",
			setup: func(_ *testing.T, env *domainTestEnv, d *domain.Domain) {
				env.resolver.set("validation."+d.Domain, testCluster)
			},
			user: accountAMember,
			want: status.PermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupDomainTest(t)
			d, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "test.example.com", testCluster)
			require.NoError(t, err)
			tt.setup(t, env, d)
			user := accountAUser
			if tt.user != "" {
				user = tt.user
			}

			err = env.manager.ValidateDomain(ctx, accountA, user, d.ID)
			sErr, ok := status.FromError(err)
			require.True(t, ok, "expected a status error, got %v", err)
			assert.Equal(t, tt.want, sErr.Type(), "status type")
			if tt.message != "" {
				assert.Equal(t, tt.message, sErr.Message, "user-facing message")
			}
			assert.False(t, storedDomain(t, env.store, accountA, d.Domain).Validated, "a failed check must not validate the domain")
		})
	}
}

func TestValidateDomain_SuccessIsIdempotent(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)
	d, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "ok.example.com", testCluster)
	require.NoError(t, err)
	env.resolver.set("validation.ok.example.com", testCluster)

	require.NoError(t, env.manager.ValidateDomain(ctx, accountA, accountAUser, d.ID))
	assert.True(t, storedDomain(t, env.store, accountA, d.Domain).Validated, "domain should be validated")
	assert.NoError(t, env.manager.ValidateDomain(ctx, accountA, accountAUser, d.ID), "an already validated domain is a success")
}

func setDomainColumn(t *testing.T, env *domainTestEnv, d *domain.Domain, column string, value any) {
	t.Helper()
	db := env.store.(*nbstore.SqlStore).GetDB()
	require.NoError(t, db.Model(&domain.Domain{}).Where("id = ?", d.ID).Update(column, value).Error)
}

// Two verify requests can both read the domain as pending. The one that loses the store
// update must still report success when the other one validated the domain.
func TestValidateDomain_ConcurrentValidationSucceeds(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)
	d, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "twice.example.com", testCluster)
	require.NoError(t, err)
	resolver := blockingDomainResolver{started: make(chan struct{}), release: make(chan struct{})}
	env.manager.validator.Resolver = resolver

	done := make(chan error, 1)
	go func() {
		done <- env.manager.ValidateDomain(ctx, accountA, accountAUser, d.ID)
	}()
	<-resolver.started
	// The other request completes while this one is still looking up the CNAME.
	setDomainColumn(t, env, d, "validated", true)
	close(resolver.release)

	assert.NoError(t, <-done, "a domain validated by a concurrent request is a success")
}
