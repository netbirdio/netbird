package agentnetwork

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// bootstrapFixture wires a real sqlite store to a gomock permissions manager
// so tests can grant or deny the settings permission per case.
type bootstrapFixture struct {
	manager Manager
	store   store.Store
	perms   *permissions.MockManager
}

func newBootstrapFixture(t *testing.T) *bootstrapFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sqlite store not properly supported on Windows yet")
	}
	t.Setenv("NETBIRD_STORE_ENGINE", string(nbtypes.SqliteStoreEngine))

	st, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err, "test store setup must succeed")
	t.Cleanup(cleanUp)

	ctrl := gomock.NewController(t)
	perms := permissions.NewMockManager(ctrl)

	accounts := account.NewMockManager(ctrl)
	accounts.EXPECT().StoreEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	accounts.EXPECT().UpdateAccountPeers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	accounts.EXPECT().BufferUpdateAccountPeers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	return &bootstrapFixture{
		manager: NewManager(st, perms, accounts, nil),
		store:   st,
		perms:   perms,
	}
}

func (f *bootstrapFixture) expectPermission(accountID, userID string, module modules.Module, op operations.Operation, allowed bool) {
	f.perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), accountID, userID, module, op).
		Return(allowed, context.Background(), nil)
}

func (f *bootstrapFixture) createSettings(ctx context.Context, accountID, userID, proxyAddress, endpoint string) (*types.Settings, error) {
	return f.manager.CreateSettings(ctx, userID, types.DefaultSettings(accountID), proxyAddress, endpoint)
}

func ptrTo[T any](v T) *T { return &v }

// seedProxy registers a proxy in clusterAddr, heartbeating now, so the labeled
// bootstrap path has a real cluster to validate against. accountID empty makes
// it a shared (NetBird-operated) cluster; private mirrors the capability an
// embedded `netbird proxy` reports, nil an unreported one.
func (f *bootstrapFixture) seedProxy(t *testing.T, proxyID, accountID, clusterAddr string, private *bool) {
	t.Helper()
	f.seedProxyAt(t, proxyID, accountID, clusterAddr, private, time.Now().UTC())
}

// seedProxyAt is seedProxy with an explicit last-seen, for cases that need a
// proxy whose heartbeat has aged past the active window while its row (and so
// its cluster) is still on record.
func (f *bootstrapFixture) seedProxyAt(t *testing.T, proxyID, accountID, clusterAddr string, private *bool, lastSeen time.Time) {
	t.Helper()
	p := &proxy.Proxy{
		ID:             proxyID,
		ClusterAddress: clusterAddr,
		Status:         proxy.StatusConnected,
		LastSeen:       lastSeen,
		Capabilities:   proxy.Capabilities{Private: private},
	}
	if accountID != "" {
		p.AccountID = &accountID
	}
	require.NoError(t, f.store.SaveProxy(context.Background(), p), "seeding a proxy must succeed")
}

// seedEmbeddedCluster is the common case: a shared cluster with a connected
// embedded proxy, which is what the labeled bootstrap requires.
func (f *bootstrapFixture) seedEmbeddedCluster(t *testing.T, clusterAddr string) {
	t.Helper()
	f.seedProxy(t, "proxy-"+clusterAddr, "", clusterAddr, ptrTo(true))
}

// TestCreateSettingsRequiresPermission pins the gate: bootstrap assigns the
// account's immutable endpoint, a settings write requiring the settings
// Create permission — and a denial leaves no row behind.
func TestCreateSettingsRequiresPermission(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, false)

	_, err := f.createSettings(ctx, "account1", "user1", "cluster1.example.com", "")
	require.Error(t, err, "bootstrap without the settings permission must fail")
	var sErr *status.Error
	require.ErrorAs(t, err, &sErr)
	assert.Equal(t, status.PermissionDenied, sErr.Type(), "denial should surface as permission denied")

	_, err = f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "account1")
	assert.Error(t, err, "settings row must not be created when bootstrap is denied")
}

// TestCreateSettingsLabeled pins the labeled shape: the server allocates an
// adjective-noun label beneath the proxy address, the pin is not dedicated,
// and the domain records the full endpoint hostname.
func TestCreateSettingsLabeled(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.seedEmbeddedCluster(t, "cluster1.example.com")
	f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

	created, err := f.createSettings(ctx, "account1", "user1", "Cluster1.Example.com", "")
	require.NoError(t, err, "labeled bootstrap must succeed")
	assert.Equal(t, "cluster1.example.com", created.ProxyAddress, "proxy address must be pinned lowercased")
	require.True(t, strings.HasSuffix(created.Domain, ".cluster1.example.com"),
		"domain must hang one label beneath the proxy address: %s", created.Domain)
	label := strings.TrimSuffix(created.Domain, ".cluster1.example.com")
	assert.NotContains(t, label, ".", "the allocated label must be a single DNS label: %s", label)
	assert.False(t, created.Dedicated(), "a labeled pin is not dedicated")
	assert.Equal(t, created.Domain, created.Endpoint(), "the endpoint is the domain column")

	stored, err := f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "account1")
	require.NoError(t, err, "bootstrap must persist the row")
	assert.Equal(t, created.Domain, stored.Domain)
	assert.Equal(t, created.ProxyAddress, stored.ProxyAddress)
}

// TestCreateSettingsSelfAddressed pins the dedicated shape: the endpoint is
// claimed verbatim (normalized), Domain == ProxyAddress, and the claim
// succeeds with no proxy declaring the address yet (address-first).
func TestCreateSettingsSelfAddressed(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

	created, err := f.createSettings(ctx, "account1", "user1", "", "Brave-Otter.GW.Example.com")
	require.NoError(t, err, "self-addressed bootstrap must succeed")
	assert.Equal(t, "brave-otter.gw.example.com", created.Domain, "endpoint must be claimed lowercased")
	assert.Equal(t, created.Domain, created.ProxyAddress, "self-addressed: proxy address is the endpoint")
	assert.True(t, created.Dedicated(), "a self-addressed pin is dedicated")
}

// TestCreateSettingsIdentityFieldValidation pins the request contract: exactly
// one of proxyAddress and endpoint, and both must be well-formed hostnames.
func TestCreateSettingsIdentityFieldValidation(t *testing.T) {
	ctx := context.Background()

	cases := map[string]struct {
		proxyAddress string
		endpoint     string
	}{
		"neither":               {"", ""},
		"both":                  {"cluster1.example.com", "gw.example.com"},
		"trailing dot endpoint": {"", "gw.example.com."},
		"leading dot endpoint":  {"", ".gw.example.com"},
		"whitespace inside":     {"", "g w.example.com"},
		"empty label in parent": {"eu..example.com", ""},
		"hyphen-edged label":    {"", "-gw.example.com"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBootstrapFixture(t)
			f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

			_, err := f.createSettings(ctx, "account1", "user1", tc.proxyAddress, tc.endpoint)
			require.Error(t, err, "invalid identity input must be rejected")
			var sErr *status.Error
			require.ErrorAs(t, err, &sErr)
			assert.Equal(t, status.InvalidArgument, sErr.Type(), "rejection must be a validation error")

			_, err = f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "account1")
			assert.Error(t, err, "no row may be left behind by a rejected bootstrap")
		})
	}
}

// TestCreateSettingsConflictsOnSecondBootstrap pins that bootstrap is a
// one-time create per account: a second call is a conflict, whatever shape it
// asks for, and the original row survives untouched.
func TestCreateSettingsConflictsOnSecondBootstrap(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.seedEmbeddedCluster(t, "cluster1.example.com")
	f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

	first, err := f.createSettings(ctx, "account1", "user1", "cluster1.example.com", "")
	require.NoError(t, err)

	f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)
	_, err = f.createSettings(ctx, "account1", "user1", "", "other.example.com")
	require.Error(t, err, "second bootstrap must fail")
	var sErr *status.Error
	require.ErrorAs(t, err, &sErr)
	assert.Equal(t, status.AlreadyExists, sErr.Type(), "second bootstrap must surface as a conflict")

	stored, err := f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "account1")
	require.NoError(t, err)
	assert.Equal(t, first.Domain, stored.Domain, "the original endpoint must survive the rejected bootstrap")
}

// TestCreateSettingsEndpointTaken pins global hostname uniqueness: a hostname
// held by one account cannot be claimed by another, in either direction —
// self-addressed onto self-addressed, or self-addressed onto an allocated
// labeled endpoint.
func TestCreateSettingsEndpointTaken(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)

	f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)
	first, err := f.createSettings(ctx, "account1", "user1", "", "gw.example.com")
	require.NoError(t, err)

	f.expectPermission("account2", "user2", modules.AgentNetworkSettings, operations.Create, true)
	_, err = f.createSettings(ctx, "account2", "user2", "", "gw.example.com")
	require.Error(t, err, "a taken hostname must be refused")
	var sErr *status.Error
	require.ErrorAs(t, err, &sErr)
	assert.Equal(t, status.AlreadyExists, sErr.Type(), "the refusal must surface as a conflict")

	f.expectPermission("account3", "user3", modules.AgentNetworkSettings, operations.Create, true)
	_, err = f.createSettings(ctx, "account3", "user3", "", first.Domain)
	require.Error(t, err, "claiming another account's endpoint must be refused")
}

// TestCreateProviderHasNoSettingsSideEffects pins the decoupling: provider
// create needs only the providers permission (gomock fails the test on any
// settings-permission call) and never creates a settings row.
func TestCreateProviderHasNoSettingsSideEffects(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	provider := types.NewProvider("account1")
	provider.Name = "openai"
	provider.UpstreamURL = "https://api.openai.com"
	provider.APIKey = "sk-test"
	provider.Enabled = true

	created, err := f.manager.CreateProvider(ctx, "user1", provider)
	require.NoError(t, err, "provider create must succeed on the providers permission alone")
	require.NotNil(t, created)

	_, err = f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "account1")
	assert.Error(t, err, "provider create must not conjure a settings row")
}

// TestCreateSettingsAllowsUnknownCluster pins the one opening left: a cluster
// management holds no proxy row for cannot be judged, so the pin is allowed —
// the same order the dedicated path documents (claim the address, connect the
// proxy after).
func TestCreateSettingsAllowsUnknownCluster(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

	created, err := f.createSettings(ctx, "account1", "user1", "future.example.com", "")
	require.NoError(t, err, "a cluster no proxy has ever declared must stay pinnable")
	assert.Equal(t, "future.example.com", created.ProxyAddress)
}

// TestCreateSettingsRejectsOfflineCluster is the guard against deciding on
// heartbeat freshness. A centralised cluster is refused while its proxies are
// live; the same cluster must stay refused once they stop heartbeating, which
// takes only a couple of minutes (proxyActiveThreshold). Judging on liveness
// would turn "wait for the proxy to go quiet" into a way to pin the account's
// immutable endpoint to a cluster that can never serve it.
func TestCreateSettingsRejectsOfflineCluster(t *testing.T) {
	ctx := context.Background()
	notPrivate := false

	cases := map[string]*bool{
		"centralised proxy gone quiet": &notPrivate,
		// A cluster that could serve the gateway still has to have something
		// live in it to prove so at bootstrap: refusing is the safe direction
		// (reconnect the proxy and retry) where accepting is permanent.
		"embedded proxy gone quiet": ptrTo(true),
	}
	for name, private := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBootstrapFixture(t)
			f.seedProxyAt(t, "proxy1", "", "offline.example.com", private,
				time.Now().UTC().Add(-time.Hour))
			f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

			_, err := f.createSettings(ctx, "account1", "user1", "offline.example.com", "")
			require.Error(t, err, "a known cluster with nothing live in it must be rejected")
			var sErr *status.Error
			require.ErrorAs(t, err, &sErr)
			assert.Equal(t, status.InvalidArgument, sErr.Type(), "rejection must be a validation error")
			assert.Contains(t, err.Error(), "connected embedded proxy",
				"the error must say a live embedded proxy is what is missing")

			_, err = f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "account1")
			assert.Error(t, err, "no row may be left behind by a rejected bootstrap")
		})
	}
}

// TestCreateSettingsRequiresPrivateCluster pins the capability gate: the
// synthesised gateway service is always private, so a live cluster whose
// proxies are not embedded in a netbird client cannot serve it and must not
// become the account's immutable endpoint.
func TestCreateSettingsRequiresPrivateCluster(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	notPrivate := false
	f.seedProxy(t, "proxy1", "", "central.example.com", &notPrivate)
	f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

	_, err := f.createSettings(ctx, "account1", "user1", "central.example.com", "")
	require.Error(t, err, "a cluster without an embedded proxy must be rejected")
	var sErr *status.Error
	require.ErrorAs(t, err, &sErr)
	assert.Equal(t, status.InvalidArgument, sErr.Type(), "rejection must be a validation error")
	assert.Contains(t, err.Error(), "embedded proxy", "the error must name what the cluster is missing")

	_, err = f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "account1")
	assert.Error(t, err, "no row may be left behind by a rejected bootstrap")
}

// TestCreateSettingsRejectsForeignCluster pins tenant isolation on the pin: an
// account-owned (BYOP) cluster belongs to the account that runs it and is not
// one another account may hang its gateway beneath, even though it is
// private-capable. Ownership does not lapse with the heartbeat either, so the
// refusal holds while the foreign cluster is offline.
func TestCreateSettingsRejectsForeignCluster(t *testing.T) {
	ctx := context.Background()

	cases := map[string]time.Time{
		"live":    time.Now().UTC(),
		"offline": time.Now().UTC().Add(-time.Hour),
	}
	for name, lastSeen := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBootstrapFixture(t)
			f.seedProxyAt(t, "proxy1", "account2", "byop.account2.example.com", ptrTo(true), lastSeen)
			f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

			_, err := f.createSettings(ctx, "account1", "user1", "byop.account2.example.com", "")
			require.Error(t, err, "another account's BYOP cluster must be rejected")
			var sErr *status.Error
			require.ErrorAs(t, err, &sErr)
			assert.Equal(t, status.InvalidArgument, sErr.Type(), "rejection must be a validation error")
			assert.Contains(t, err.Error(), "not available to this account",
				"the error must say the cluster is not the account's to use")
		})
	}
}

// TestCreateSettingsAcceptsOwnPrivateCluster pins the BYOP happy path: the
// account's own cluster with a connected embedded proxy is a valid pin.
func TestCreateSettingsAcceptsOwnPrivateCluster(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.seedProxy(t, "proxy1", "account1", "byop.account1.example.com", ptrTo(true))
	f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

	created, err := f.createSettings(ctx, "account1", "user1", "byop.account1.example.com", "")
	require.NoError(t, err, "the account's own private cluster must be accepted")
	assert.Equal(t, "byop.account1.example.com", created.ProxyAddress)
}
