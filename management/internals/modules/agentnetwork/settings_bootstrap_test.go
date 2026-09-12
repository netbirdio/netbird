package agentnetwork

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

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
	// vendor stands in for the provider credential check's vendor call, which
	// runs on every provider write. Without it these tests would reach a real
	// vendor to save a record.
	vendor *stubLister
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

	vendor := &stubLister{}
	return &bootstrapFixture{
		manager: NewManager(st, perms, accounts, nil, WithModelLister(vendor)),
		store:   st,
		perms:   perms,
		vendor:  vendor,
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

// requireForeignClusterRefusal asserts the refusal a pin onto another
// account's host gets, and that it left no row behind.
func (f *bootstrapFixture) requireForeignClusterRefusal(t *testing.T, err error, accountID string) {
	t.Helper()
	require.Error(t, err, "another account's host must be refused")
	var sErr *status.Error
	require.ErrorAs(t, err, &sErr)
	assert.Equal(t, status.InvalidArgument, sErr.Type(), "rejection must be a validation error")
	assert.Contains(t, err.Error(), "not available to this account",
		"the error must say the host is not the account's to use")

	_, err = f.store.GetAgentNetworkSettings(context.Background(), store.LockingStrengthNone, accountID)
	assert.Error(t, err, "no row may be left behind by a rejected bootstrap")
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
	provider.ProviderID = "openai_api"
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

// TestCreateSettingsRejectsForeignCluster pins tenant consistency on the pin:
// an account may not pin its gateway onto a host another account's proxy
// declares. That proxy only ever receives its own account's mappings, so the
// pin could never be served, and the endpoint it assigns is immutable.
// Ownership is decided on the proxy rows, not on heartbeat freshness — a
// cluster whose proxies are merely offline is still somebody's — and on the
// normalised host, since proxies declare their address as the operator
// spelled it.
func TestCreateSettingsRejectsForeignCluster(t *testing.T) {
	ctx := context.Background()

	cases := map[string]struct {
		spelling string
		lastSeen time.Time
	}{
		"live":            {"byop.account2.example.com", time.Now().UTC()},
		"offline":         {"byop.account2.example.com", time.Now().UTC().Add(-time.Hour)},
		"spelled in caps": {"BYOP.Account2.Example.com", time.Now().UTC()},
	}
	for name, tc := range cases {
		t.Run("labeled "+name, func(t *testing.T) {
			f := newBootstrapFixture(t)
			f.seedProxyAt(t, "proxy1", "account2", tc.spelling, ptrTo(true), tc.lastSeen)
			f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

			_, err := f.createSettings(ctx, "account1", "user1", "byop.account2.example.com", "")
			f.requireForeignClusterRefusal(t, err, "account1")
		})
		t.Run("self-addressed "+name, func(t *testing.T) {
			f := newBootstrapFixture(t)
			f.seedProxyAt(t, "proxy1", "account2", tc.spelling, ptrTo(true), tc.lastSeen)
			f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

			_, err := f.createSettings(ctx, "account1", "user1", "", "byop.account2.example.com")
			f.requireForeignClusterRefusal(t, err, "account1")
		})
	}
}

// TestCreateSettingsSharedClusterStaysPinnable pins the constraint the
// ownership check must respect: a shared (NetBird-operated) cluster is not
// anybody's, so any number of accounts pin their gateways to it — including
// an account that also runs a proxy of its own elsewhere.
func TestCreateSettingsSharedClusterStaysPinnable(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.seedProxy(t, "shared", "", "eu.proxy.netbird.io", ptrTo(true))
	f.seedProxy(t, "own", "account1", "byop.account1.example.com", ptrTo(true))

	for _, account := range []string{"account1", "account2"} {
		f.expectPermission(account, "user", modules.AgentNetworkSettings, operations.Create, true)
		created, err := f.createSettings(ctx, account, "user", "eu.proxy.netbird.io", "")
		require.NoError(t, err, "a shared cluster must stay pinnable by %s", account)
		assert.Equal(t, "eu.proxy.netbird.io", created.ProxyAddress)
	}
}

// TestCreateSettingsOwnClusterIsPinnable is the BYOP order in both directions:
// the account's own proxy is not a competing claim, whether the pin is labeled
// beneath its cluster or self-addressed onto the very host it declares.
func TestCreateSettingsOwnClusterIsPinnable(t *testing.T) {
	ctx := context.Background()

	t.Run("labeled", func(t *testing.T) {
		f := newBootstrapFixture(t)
		f.seedProxy(t, "own", "account1", "byop.account1.example.com", ptrTo(true))
		f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

		created, err := f.createSettings(ctx, "account1", "user1", "byop.account1.example.com", "")
		require.NoError(t, err, "the account's own cluster must be pinnable")
		assert.True(t, strings.HasSuffix(created.Domain, ".byop.account1.example.com"))
	})
	t.Run("self-addressed", func(t *testing.T) {
		f := newBootstrapFixture(t)
		f.seedProxy(t, "own", "account1", "gw.account1.example.com", ptrTo(true))
		f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

		created, err := f.createSettings(ctx, "account1", "user1", "", "gw.account1.example.com")
		require.NoError(t, err, "the host the account's own proxy declares must be pinnable")
		assert.Equal(t, "gw.account1.example.com", created.ProxyAddress)
	})
}

// TestCreateSettingsUnknownHostIsPinnable pins the address-first order: a host
// no proxy has ever declared is nobody's, so the pin goes through and the
// proxy is deployed after.
func TestCreateSettingsUnknownHostIsPinnable(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

	created, err := f.createSettings(ctx, "account1", "user1", "future.example.com", "")
	require.NoError(t, err, "a host no proxy has declared must stay pinnable")
	assert.Equal(t, "future.example.com", created.ProxyAddress)
}

// TestCreateSettingsRejectsHostAnotherAccountPinned covers claims made by pins
// rather than proxies, which the proxy-row check cannot see. A labeled pin
// beneath a host makes that host the other account's cluster, so a
// self-addressed endpoint on it would never be served; a self-addressed
// endpoint on a host makes the proxy declaring it theirs, so a label beneath
// it would never be served either. Neither is a shared-cluster shape: many
// labeled pins under one cluster are asked about in neither direction.
func TestCreateSettingsRejectsHostAnotherAccountPinned(t *testing.T) {
	ctx := context.Background()

	t.Run("self-addressed onto another account's cluster", func(t *testing.T) {
		f := newBootstrapFixture(t)
		f.expectPermission("account2", "user2", modules.AgentNetworkSettings, operations.Create, true)
		_, err := f.createSettings(ctx, "account2", "user2", "gw.example.com", "")
		require.NoError(t, err, "account2's labeled pin beneath the host must go through first")

		f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)
		_, err = f.createSettings(ctx, "account1", "user1", "", "gw.example.com")
		f.requireForeignClusterRefusal(t, err, "account1")
	})

	t.Run("labeled beneath another account's endpoint", func(t *testing.T) {
		f := newBootstrapFixture(t)
		f.expectPermission("account2", "user2", modules.AgentNetworkSettings, operations.Create, true)
		_, err := f.createSettings(ctx, "account2", "user2", "", "gw.example.com")
		require.NoError(t, err, "account2's self-addressed endpoint must go through first")

		f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)
		_, err = f.createSettings(ctx, "account1", "user1", "gw.example.com", "")
		f.requireForeignClusterRefusal(t, err, "account1")
	})

	t.Run("labeled beside another account's labeled pin stays allowed", func(t *testing.T) {
		f := newBootstrapFixture(t)
		for _, account := range []string{"account1", "account2"} {
			f.expectPermission(account, "user", modules.AgentNetworkSettings, operations.Create, true)
			_, err := f.createSettings(ctx, account, "user", "eu.proxy.netbird.io", "")
			require.NoError(t, err, "labeled pins under one cluster are the shared-cluster shape and must not refuse each other")
		}
	})
}
