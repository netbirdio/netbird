package manager

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/status"
)

func TestCreateDomain_NormalizesName(t *testing.T) {
	for _, tt := range []struct {
		name      string
		input     string
		canonical string
	}{
		{"mixed case", "Apps.Example.COM", "apps.example.com"},
		{"unicode", "münchen.example.com", "xn--mnchen-3ya.example.com"},
		{"trailing dot", "apps.example.com.", "apps.example.com"},
		{"underscore", "My_App.example.com", "my_app.example.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			env := setupDomainTest(t)
			env.resolver.set("validation."+tt.canonical, testCluster)

			created, err := env.manager.CreateDomain(ctx, accountA, accountAUser, tt.input, testCluster)
			require.NoError(t, err)
			assert.Equal(t, tt.canonical, created.Domain, "the response must use the normalized name")
			assert.True(t, created.Validated, "the CNAME lookup must use the normalized name")
			stored, err := env.store.GetCustomDomain(ctx, accountA, created.ID)
			require.NoError(t, err)
			assert.Equal(t, tt.canonical, stored.Domain, "the database must retain the normalized name")

			_, err = env.manager.CreateDomain(ctx, accountB, accountBUser, tt.canonical, testCluster)
			require.Error(t, err)
			sErr, ok := status.FromError(err)
			require.True(t, ok, "an equivalent name must return a typed conflict")
			assert.Equal(t, status.AlreadyExists, sErr.Type(), "normalization must precede the availability check")
		})
	}
}

func TestCreateDomain_NormalizedNameCanValidateLater(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)
	created, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "Apps.Example.COM.", testCluster)
	require.NoError(t, err)
	require.False(t, created.Validated, "a missing CNAME must leave the normalized registration pending")

	env.resolver.set("validation.apps.example.com", testCluster)
	env.manager.ValidateDomain(ctx, accountA, accountAUser, created.ID)
	stored, err := env.store.GetCustomDomain(ctx, accountA, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "apps.example.com", stored.Domain, "retrying validation must retain the normalized name")
	assert.True(t, stored.Validated, "later validation must look up the normalized name")
}

func TestCreateDomain_RejectsInvalidName(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)
	for _, name := range []string{
		"", ".", "app..example.com", "app.example.com..", "-app.example.com",
		"app%.example.com", "app!.example.com", "*.example.com", "app example.com",
		"https://example.com", strings.Repeat("a", 64) + ".example.com",
	} {
		t.Run(name, func(t *testing.T) {
			// A matching DNS response must not make a malformed name acceptable.
			env.resolver.set("validation."+name, testCluster)
			_, err := env.manager.CreateDomain(ctx, accountA, accountAUser, name, testCluster)
			require.Error(t, err)
			sErr, ok := status.FromError(err)
			require.True(t, ok, "invalid names must return a typed client error")
			assert.Equal(t, status.InvalidArgument, sErr.Type(), "malformed names must be rejected before storage")
		})
	}
	stored, err := env.store.ListCustomDomains(ctx, accountA)
	require.NoError(t, err)
	assert.Empty(t, stored, "invalid registration attempts must not reserve any names")
}
