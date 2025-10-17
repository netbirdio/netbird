package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) GetAccountSlow(ctx context.Context, accountID string) (*types.Account, error) {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		if elapsed > 1*time.Second {
			log.WithContext(ctx).Tracef("GetAccount for account %s exceeded 1s, took: %v", accountID, elapsed)
		}
	}()

	var account types.Account
	result := s.db.Model(&account).
		Omit("GroupsG").
		Preload("UsersG.PATsG"). // have to be specifies as this is nester reference
		Preload(clause.Associations).
		Take(&account, idQueryCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("error when getting account %s from the store: %s", accountID, result.Error)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		return nil, status.NewGetAccountFromStoreError(result.Error)
	}

	// we have to manually preload policy rules as it seems that gorm preloading doesn't do it for us
	for i, policy := range account.Policies {
		var rules []*types.PolicyRule
		err := s.db.Model(&types.PolicyRule{}).Find(&rules, "policy_id = ?", policy.ID).Error
		if err != nil {
			return nil, status.Errorf(status.NotFound, "rule not found")
		}
		account.Policies[i].Rules = rules
	}

	account.SetupKeys = make(map[string]*types.SetupKey, len(account.SetupKeysG))
	for _, key := range account.SetupKeysG {
		account.SetupKeys[key.Key] = key.Copy()
	}
	account.SetupKeysG = nil

	account.Peers = make(map[string]*nbpeer.Peer, len(account.PeersG))
	for _, peer := range account.PeersG {
		account.Peers[peer.ID] = peer.Copy()
	}
	account.PeersG = nil

	account.Users = make(map[string]*types.User, len(account.UsersG))
	for _, user := range account.UsersG {
		user.PATs = make(map[string]*types.PersonalAccessToken, len(user.PATs))
		for _, pat := range user.PATsG {
			user.PATs[pat.ID] = pat.Copy()
		}
		account.Users[user.Id] = user.Copy()
	}
	account.UsersG = nil

	account.Groups = make(map[string]*types.Group, len(account.GroupsG))
	for _, group := range account.GroupsG {
		account.Groups[group.ID] = group.Copy()
	}
	account.GroupsG = nil

	var groupPeers []types.GroupPeer
	s.db.Model(&types.GroupPeer{}).Where("account_id = ?", accountID).
		Find(&groupPeers)
	for _, groupPeer := range groupPeers {
		if group, ok := account.Groups[groupPeer.GroupID]; ok {
			group.Peers = append(group.Peers, groupPeer.PeerID)
		} else {
			log.WithContext(ctx).Warnf("group %s not found for group peer %s in account %s", groupPeer.GroupID, groupPeer.PeerID, accountID)
		}
	}

	account.Routes = make(map[route.ID]*route.Route, len(account.RoutesG))
	for _, route := range account.RoutesG {
		account.Routes[route.ID] = route.Copy()
	}
	account.RoutesG = nil

	account.NameServerGroups = make(map[string]*nbdns.NameServerGroup, len(account.NameServerGroupsG))
	for _, ns := range account.NameServerGroupsG {
		account.NameServerGroups[ns.ID] = ns.Copy()
	}
	account.NameServerGroupsG = nil

	return &account, nil
}

func connectDBforTest(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database config: %w", err)
	}

	config.MaxConns = 10
	config.MinConns = 2
	config.MaxConnLifetime = time.Hour
	config.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	fmt.Println("Successfully connected to the database!")
	return pool, nil
}

func setupBenchmarkDB(b testing.TB) (*SqlStore, string) {
	dsn := "host=localhost user=postgres password=mysecretpassword dbname=testdb port=5432 sslmode=disable TimeZone=Europe/Berlin"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		b.Fatalf("failed to connect database: %v", err)
	}

	pool, err := connectDB(context.Background(), dsn)
	if err != nil {
		b.Fatalf("failed to connect database: %v", err)
	}

	models := []interface{}{
		&types.Account{}, &types.SetupKey{}, &nbpeer.Peer{}, &types.User{},
		&types.PersonalAccessToken{}, &types.Group{}, &types.GroupPeer{},
		&types.Policy{}, &types.PolicyRule{}, &route.Route{},
		&nbdns.NameServerGroup{}, &posture.Checks{}, &networkTypes.Network{},
		&routerTypes.NetworkRouter{}, &resourceTypes.NetworkResource{},
		&types.AccountOnboarding{},
	}

	for i := len(models) - 1; i >= 0; i-- {
		db.Migrator().DropTable(models[i])
	}

	err = db.AutoMigrate(models...)
	if err != nil {
		b.Fatalf("failed to migrate database: %v", err)
	}

	store := &SqlStore{
		db:   db,
		pool: pool,
	}

	const (
		accountID           = "benchmark-account-id"
		numUsers            = 20
		numPatsPerUser      = 3
		numSetupKeys        = 25
		numPeers            = 200
		numGroups           = 30
		numPolicies         = 50
		numRulesPerPolicy   = 10
		numRoutes           = 40
		numNSGroups         = 10
		numPostureChecks    = 15
		numNetworks         = 5
		numNetworkRouters   = 5
		numNetworkResources = 10
	)

	_, ipNet, _ := net.ParseCIDR("100.64.0.0/10")
	acc := types.Account{
		Id:                     accountID,
		CreatedBy:              "benchmark-user",
		CreatedAt:              time.Now(),
		Domain:                 "benchmark.com",
		IsDomainPrimaryAccount: true,
		Network: &types.Network{
			Identifier: "benchmark-net",
			Net:        *ipNet,
			Serial:     1,
		},
		DNSSettings: types.DNSSettings{
			DisabledManagementGroups: []string{"group-disabled-1"},
		},
		Settings: &types.Settings{},
	}
	if err := db.Create(&acc).Error; err != nil {
		b.Fatalf("create account: %v", err)
	}

	var setupKeys []types.SetupKey
	for i := 0; i < numSetupKeys; i++ {
		setupKeys = append(setupKeys, types.SetupKey{
			Id:        fmt.Sprintf("keyid-%d", i),
			AccountID: accountID,
			Key:       fmt.Sprintf("key-%d", i),
			Name:      fmt.Sprintf("Benchmark Key %d", i),
			ExpiresAt: &time.Time{},
		})
	}
	if err := db.Create(&setupKeys).Error; err != nil {
		b.Fatalf("create setup keys: %v", err)
	}

	var peers []nbpeer.Peer
	for i := 0; i < numPeers; i++ {
		peers = append(peers, nbpeer.Peer{
			ID:        fmt.Sprintf("peer-%d", i),
			AccountID: accountID,
			Key:       fmt.Sprintf("peerkey-%d", i),
			IP:        net.ParseIP(fmt.Sprintf("100.64.0.%d", i+1)),
			Name:      fmt.Sprintf("peer-name-%d", i),
			Status:    &nbpeer.PeerStatus{Connected: i%2 == 0, LastSeen: time.Now()},
		})
	}
	if err := db.Create(&peers).Error; err != nil {
		b.Fatalf("create peers: %v", err)
	}

	for i := 0; i < numUsers; i++ {
		userID := fmt.Sprintf("user-%d", i)
		user := types.User{Id: userID, AccountID: accountID}
		if err := db.Create(&user).Error; err != nil {
			b.Fatalf("create user %s: %v", userID, err)
		}

		var pats []types.PersonalAccessToken
		for j := 0; j < numPatsPerUser; j++ {
			pats = append(pats, types.PersonalAccessToken{
				ID:     fmt.Sprintf("pat-%d-%d", i, j),
				UserID: userID,
				Name:   fmt.Sprintf("PAT %d for User %d", j, i),
			})
		}
		if err := db.Create(&pats).Error; err != nil {
			b.Fatalf("create pats for user %s: %v", userID, err)
		}
	}

	var groups []*types.Group
	for i := 0; i < numGroups; i++ {
		groups = append(groups, &types.Group{
			ID:        fmt.Sprintf("group-%d", i),
			AccountID: accountID,
			Name:      fmt.Sprintf("Group %d", i),
		})
	}
	if err := db.Create(&groups).Error; err != nil {
		b.Fatalf("create groups: %v", err)
	}

	for i := 0; i < numPolicies; i++ {
		policyID := fmt.Sprintf("policy-%d", i)
		policy := types.Policy{ID: policyID, AccountID: accountID, Name: fmt.Sprintf("Policy %d", i), Enabled: true}
		if err := db.Create(&policy).Error; err != nil {
			b.Fatalf("create policy %s: %v", policyID, err)
		}

		var rules []*types.PolicyRule
		for j := 0; j < numRulesPerPolicy; j++ {
			rules = append(rules, &types.PolicyRule{
				ID:       fmt.Sprintf("rule-%d-%d", i, j),
				PolicyID: policyID,
				Name:     fmt.Sprintf("Rule %d for Policy %d", j, i),
				Enabled:  true,
				Protocol: "all",
			})
		}
		if err := db.Create(&rules).Error; err != nil {
			b.Fatalf("create rules for policy %s: %v", policyID, err)
		}
	}

	var routes []route.Route
	for i := 0; i < numRoutes; i++ {
		routes = append(routes, route.Route{
			ID:          route.ID(fmt.Sprintf("route-%d", i)),
			AccountID:   accountID,
			Description: fmt.Sprintf("Route %d", i),
			Network:     netip.MustParsePrefix(fmt.Sprintf("192.168.%d.0/24", i)),
			Enabled:     true,
		})
	}
	if err := db.Create(&routes).Error; err != nil {
		b.Fatalf("create routes: %v", err)
	}

	var nsGroups []nbdns.NameServerGroup
	for i := 0; i < numNSGroups; i++ {
		nsGroups = append(nsGroups, nbdns.NameServerGroup{
			ID:          fmt.Sprintf("nsg-%d", i),
			AccountID:   accountID,
			Name:        fmt.Sprintf("NS Group %d", i),
			Description: "Benchmark NS Group",
			Enabled:     true,
		})
	}
	if err := db.Create(&nsGroups).Error; err != nil {
		b.Fatalf("create nsgroups: %v", err)
	}

	var postureChecks []*posture.Checks
	for i := 0; i < numPostureChecks; i++ {
		postureChecks = append(postureChecks, &posture.Checks{
			ID:        fmt.Sprintf("pc-%d", i),
			AccountID: accountID,
			Name:      fmt.Sprintf("Posture Check %d", i),
		})
	}
	if err := db.Create(&postureChecks).Error; err != nil {
		b.Fatalf("create posture checks: %v", err)
	}

	var networks []*networkTypes.Network
	for i := 0; i < numNetworks; i++ {
		networks = append(networks, &networkTypes.Network{
			ID:        fmt.Sprintf("nettype-%d", i),
			AccountID: accountID,
			Name:      fmt.Sprintf("Network Type %d", i),
		})
	}
	if err := db.Create(&networks).Error; err != nil {
		b.Fatalf("create networks: %v", err)
	}

	var networkRouters []*routerTypes.NetworkRouter
	for i := 0; i < numNetworkRouters; i++ {
		networkRouters = append(networkRouters, &routerTypes.NetworkRouter{
			ID:        fmt.Sprintf("router-%d", i),
			AccountID: accountID,
			NetworkID: networks[i%numNetworks].ID,
			Peer:      peers[i%numPeers].ID,
		})
	}
	if err := db.Create(&networkRouters).Error; err != nil {
		b.Fatalf("create network routers: %v", err)
	}

	var networkResources []*resourceTypes.NetworkResource
	for i := 0; i < numNetworkResources; i++ {
		networkResources = append(networkResources, &resourceTypes.NetworkResource{
			ID:        fmt.Sprintf("resource-%d", i),
			AccountID: accountID,
			NetworkID: networks[i%numNetworks].ID,
			Name:      fmt.Sprintf("Resource %d", i),
		})
	}
	if err := db.Create(&networkResources).Error; err != nil {
		b.Fatalf("create network resources: %v", err)
	}

	onboarding := types.AccountOnboarding{
		AccountID:             accountID,
		OnboardingFlowPending: true,
	}
	if err := db.Create(&onboarding).Error; err != nil {
		b.Fatalf("create onboarding: %v", err)
	}

	return store, accountID
}

func BenchmarkGetAccount(b *testing.B) {
	store, accountID := setupBenchmarkDB(b)
	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	b.Run("old", func(b *testing.B) {
		for range b.N {
			_, err := store.GetAccountSlow(ctx, accountID)
			if err != nil {
				b.Fatalf("GetAccountSlow failed: %v", err)
			}
		}
	})
	b.Run("new", func(b *testing.B) {
		for range b.N {
			_, err := store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("GetAccountFast failed: %v", err)
			}
		}
	})
	b.Run("raw", func(b *testing.B) {
		for range b.N {
			_, err := store.GetAccountPureSQL(ctx, accountID)
			if err != nil {
				b.Fatalf("GetAccountPureSQL failed: %v", err)
			}
		}
	})
	store.pool.Close()
}

func TestAccountEquivalence(t *testing.T) {
	store, accountID := setupBenchmarkDB(t)
	ctx := context.Background()

	type getAccountFunc func(context.Context, string) (*types.Account, error)

	tests := []struct {
		name      string
		expectedF getAccountFunc
		actualF   getAccountFunc
	}{
		{"old vs new", store.GetAccountSlow, store.GetAccount},
		{"old vs raw", store.GetAccountSlow, store.GetAccountPureSQL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected, errOld := tt.expectedF(ctx, accountID)
			assert.NoError(t, errOld, "expected function should not return an error")
			assert.NotNil(t, expected, "expected should not be nil")

			actual, errNew := tt.actualF(ctx, accountID)
			assert.NoError(t, errNew, "actual function should not return an error")
			assert.NotNil(t, actual, "actual should not be nil")
			testAccountEquivalence(t, expected, actual)
		})
	}

	expected, errOld := store.GetAccountSlow(ctx, accountID)
	assert.NoError(t, errOld, "GetAccountSlow should not return an error")
	assert.NotNil(t, expected, "expected should not be nil")

	actual, errNew := store.GetAccount(ctx, accountID)
	assert.NoError(t, errNew, "GetAccount (new) should not return an error")
	assert.NotNil(t, actual, "actual should not be nil")
}

func testAccountEquivalence(t *testing.T, expected, actual *types.Account) {
	normalizeNilSlices(expected)
	normalizeNilSlices(actual)

	assert.Equal(t, expected.Id, actual.Id, "Account IDs should be equal")
	assert.Equal(t, expected.CreatedBy, actual.CreatedBy, "Account CreatedBy fields should be equal")
	assert.WithinDuration(t, expected.CreatedAt, actual.CreatedAt, time.Second, "Account CreatedAt timestamps should be within a second")
	assert.Equal(t, expected.Domain, actual.Domain, "Account Domains should be equal")
	assert.Equal(t, expected.DomainCategory, actual.DomainCategory, "Account DomainCategories should be equal")
	assert.Equal(t, expected.IsDomainPrimaryAccount, actual.IsDomainPrimaryAccount, "Account IsDomainPrimaryAccount flags should be equal")
	assert.Equal(t, expected.Network, actual.Network, "Embedded Account Network structs should be equal")
	assert.Equal(t, expected.DNSSettings, actual.DNSSettings, "Embedded Account DNSSettings structs should be equal")
	assert.Equal(t, expected.Onboarding, actual.Onboarding, "Embedded Account Onboarding structs should be equal")

	assert.Len(t, actual.SetupKeys, len(expected.SetupKeys), "SetupKeys maps should have the same number of elements")
	for key, oldVal := range expected.SetupKeys {
		newVal, ok := actual.SetupKeys[key]
		assert.True(t, ok, "SetupKey with key '%s' should exist in new account", key)
		assert.Equal(t, *oldVal, *newVal, "SetupKey with key '%s' should be equal", key)
	}

	assert.Len(t, actual.Peers, len(expected.Peers), "Peers maps should have the same number of elements")
	for key, oldVal := range expected.Peers {
		newVal, ok := actual.Peers[key]
		assert.True(t, ok, "Peer with ID '%s' should exist in new account", key)
		assert.Equal(t, *oldVal, *newVal, "Peer with ID '%s' should be equal", key)
	}

	assert.Len(t, actual.Users, len(expected.Users), "Users maps should have the same number of elements")
	for key, oldUser := range expected.Users {
		newUser, ok := actual.Users[key]
		assert.True(t, ok, "User with ID '%s' should exist in new account", key)

		assert.Len(t, newUser.PATs, len(oldUser.PATs), "PATs map for user '%s' should have the same size", key)
		for patKey, oldPAT := range oldUser.PATs {
			newPAT, patOk := newUser.PATs[patKey]
			assert.True(t, patOk, "PAT with ID '%s' for user '%s' should exist in new user object", patKey, key)
			assert.Equal(t, *oldPAT, *newPAT, "PAT with ID '%s' for user '%s' should be equal", patKey, key)
		}

		oldUser.PATs = nil
		newUser.PATs = nil
		assert.Equal(t, *oldUser, *newUser, "User struct for ID '%s' (without PATs) should be equal", key)
	}

	assert.Len(t, actual.Groups, len(expected.Groups), "Groups maps should have the same number of elements")
	for key, oldVal := range expected.Groups {
		newVal, ok := actual.Groups[key]
		assert.True(t, ok, "Group with ID '%s' should exist in new account", key)
		sort.Strings(oldVal.Peers)
		sort.Strings(newVal.Peers)
		assert.Equal(t, *oldVal, *newVal, "Group with ID '%s' should be equal", key)
	}

	assert.Len(t, actual.Routes, len(expected.Routes), "Routes maps should have the same number of elements")
	for key, oldVal := range expected.Routes {
		newVal, ok := actual.Routes[key]
		assert.True(t, ok, "Route with ID '%s' should exist in new account", key)
		assert.Equal(t, *oldVal, *newVal, "Route with ID '%s' should be equal", key)
	}

	assert.Len(t, actual.NameServerGroups, len(expected.NameServerGroups), "NameServerGroups maps should have the same number of elements")
	for key, oldVal := range expected.NameServerGroups {
		newVal, ok := actual.NameServerGroups[key]
		assert.True(t, ok, "NameServerGroup with ID '%s' should exist in new account", key)
		assert.Equal(t, *oldVal, *newVal, "NameServerGroup with ID '%s' should be equal", key)
	}

	assert.Len(t, actual.Policies, len(expected.Policies), "Policies slices should have the same number of elements")
	sort.Slice(expected.Policies, func(i, j int) bool { return expected.Policies[i].ID < expected.Policies[j].ID })
	sort.Slice(actual.Policies, func(i, j int) bool { return actual.Policies[i].ID < actual.Policies[j].ID })
	for i := range expected.Policies {
		sort.Slice(expected.Policies[i].Rules, func(j, k int) bool { return expected.Policies[i].Rules[j].ID < expected.Policies[i].Rules[k].ID })
		sort.Slice(actual.Policies[i].Rules, func(j, k int) bool { return actual.Policies[i].Rules[j].ID < actual.Policies[i].Rules[k].ID })
		assert.Equal(t, *expected.Policies[i], *actual.Policies[i], "Policy with ID '%s' should be equal", expected.Policies[i].ID)
	}

	assert.Len(t, actual.PostureChecks, len(expected.PostureChecks), "PostureChecks slices should have the same number of elements")
	sort.Slice(expected.PostureChecks, func(i, j int) bool { return expected.PostureChecks[i].ID < expected.PostureChecks[j].ID })
	sort.Slice(actual.PostureChecks, func(i, j int) bool { return actual.PostureChecks[i].ID < actual.PostureChecks[j].ID })
	for i := range expected.PostureChecks {
		assert.Equal(t, *expected.PostureChecks[i], *actual.PostureChecks[i], "PostureCheck with ID '%s' should be equal", expected.PostureChecks[i].ID)
	}

	assert.Len(t, actual.Networks, len(expected.Networks), "Networks slices should have the same number of elements")
	sort.Slice(expected.Networks, func(i, j int) bool { return expected.Networks[i].ID < expected.Networks[j].ID })
	sort.Slice(actual.Networks, func(i, j int) bool { return actual.Networks[i].ID < actual.Networks[j].ID })
	for i := range expected.Networks {
		assert.Equal(t, *expected.Networks[i], *actual.Networks[i], "Network with ID '%s' should be equal", expected.Networks[i].ID)
	}

	assert.Len(t, actual.NetworkRouters, len(expected.NetworkRouters), "NetworkRouters slices should have the same number of elements")
	sort.Slice(expected.NetworkRouters, func(i, j int) bool { return expected.NetworkRouters[i].ID < expected.NetworkRouters[j].ID })
	sort.Slice(actual.NetworkRouters, func(i, j int) bool { return actual.NetworkRouters[i].ID < actual.NetworkRouters[j].ID })
	for i := range expected.NetworkRouters {
		assert.Equal(t, *expected.NetworkRouters[i], *actual.NetworkRouters[i], "NetworkRouter with ID '%s' should be equal", expected.NetworkRouters[i].ID)
	}

	assert.Len(t, actual.NetworkResources, len(expected.NetworkResources), "NetworkResources slices should have the same number of elements")
	sort.Slice(expected.NetworkResources, func(i, j int) bool { return expected.NetworkResources[i].ID < expected.NetworkResources[j].ID })
	sort.Slice(actual.NetworkResources, func(i, j int) bool { return actual.NetworkResources[i].ID < actual.NetworkResources[j].ID })
	for i := range expected.NetworkResources {
		assert.Equal(t, *expected.NetworkResources[i], *actual.NetworkResources[i], "NetworkResource with ID '%s' should be equal", expected.NetworkResources[i].ID)
	}
}

func normalizeNilSlices(acc *types.Account) {
	if acc == nil {
		return
	}

	if acc.Policies == nil {
		acc.Policies = []*types.Policy{}
	}
	if acc.PostureChecks == nil {
		acc.PostureChecks = []*posture.Checks{}
	}
	if acc.Networks == nil {
		acc.Networks = []*networkTypes.Network{}
	}
	if acc.NetworkRouters == nil {
		acc.NetworkRouters = []*routerTypes.NetworkRouter{}
	}
	if acc.NetworkResources == nil {
		acc.NetworkResources = []*resourceTypes.NetworkResource{}
	}
	if acc.DNSSettings.DisabledManagementGroups == nil {
		acc.DNSSettings.DisabledManagementGroups = []string{}
	}

	for _, key := range acc.SetupKeys {
		if key.AutoGroups == nil {
			key.AutoGroups = []string{}
		}
	}

	for _, peer := range acc.Peers {
		if peer.ExtraDNSLabels == nil {
			peer.ExtraDNSLabels = []string{}
		}
	}

	for _, user := range acc.Users {
		if user.AutoGroups == nil {
			user.AutoGroups = []string{}
		}
	}

	for _, group := range acc.Groups {
		if group.Peers == nil {
			group.Peers = []string{}
		}
		if group.Resources == nil {
			group.Resources = []types.Resource{}
		}
		if group.GroupPeers == nil {
			group.GroupPeers = []types.GroupPeer{}
		}
	}

	for _, route := range acc.Routes {
		if route.Domains == nil {
			route.Domains = domain.List{}
		}
		if route.PeerGroups == nil {
			route.PeerGroups = []string{}
		}
		if route.Groups == nil {
			route.Groups = []string{}
		}
		if route.AccessControlGroups == nil {
			route.AccessControlGroups = []string{}
		}
	}

	for _, nsg := range acc.NameServerGroups {
		if nsg.NameServers == nil {
			nsg.NameServers = []nbdns.NameServer{}
		}
		if nsg.Groups == nil {
			nsg.Groups = []string{}
		}
		if nsg.Domains == nil {
			nsg.Domains = []string{}
		}
	}

	for _, policy := range acc.Policies {
		if policy.SourcePostureChecks == nil {
			policy.SourcePostureChecks = []string{}
		}
		if policy.Rules == nil {
			policy.Rules = []*types.PolicyRule{}
		}
		for _, rule := range policy.Rules {
			if rule.Destinations == nil {
				rule.Destinations = []string{}
			}
			if rule.Sources == nil {
				rule.Sources = []string{}
			}
			if rule.Ports == nil {
				rule.Ports = []string{}
			}
			if rule.PortRanges == nil {
				rule.PortRanges = []types.RulePortRange{}
			}
		}
	}

	for _, check := range acc.PostureChecks {
		if check.Checks.GeoLocationCheck != nil {
			if check.Checks.GeoLocationCheck.Locations == nil {
				check.Checks.GeoLocationCheck.Locations = []posture.Location{}
			}
		}
		if check.Checks.PeerNetworkRangeCheck != nil {
			if check.Checks.PeerNetworkRangeCheck.Ranges == nil {
				check.Checks.PeerNetworkRangeCheck.Ranges = []netip.Prefix{}
			}
		}
		if check.Checks.ProcessCheck != nil {
			if check.Checks.ProcessCheck.Processes == nil {
				check.Checks.ProcessCheck.Processes = []posture.Process{}
			}
		}
	}

	for _, router := range acc.NetworkRouters {
		if router.PeerGroups == nil {
			router.PeerGroups = []string{}
		}
	}
}

func (s *SqlStore) GetAccountPureSQL(ctx context.Context, accountID string) (*types.Account, error) {
	var account types.Account
	account.Network = &types.Network{}
	const accountQuery = `
		SELECT
			id, created_by, created_at, domain, domain_category, is_domain_primary_account,
			network_identifier, network_net, network_dns, network_serial,
			dns_settings_disabled_management_groups
		FROM accounts WHERE id = $1`

	var networkNet, dnsSettingsDisabledGroups []byte
	err := s.pool.QueryRow(ctx, accountQuery, accountID).Scan(
		&account.Id, &account.CreatedBy, &account.CreatedAt, &account.Domain, &account.DomainCategory, &account.IsDomainPrimaryAccount,
		&account.Network.Identifier, &networkNet, &account.Network.Dns, &account.Network.Serial,
		&dnsSettingsDisabledGroups,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("account not found")
		}
		return nil, err
	}
	_ = json.Unmarshal(networkNet, &account.Network.Net)
	_ = json.Unmarshal(dnsSettingsDisabledGroups, &account.DNSSettings.DisabledManagementGroups)

	var wg sync.WaitGroup
	errChan := make(chan error, 12)

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT id, account_id, key, key_secret, name, type, created_at, expires_at, updated_at, revoked, used_times, last_used, auto_groups, usage_limit, ephemeral, allow_extra_dns_labels FROM setup_keys WHERE account_id = $1`
		rows, err := s.pool.Query(ctx, query, accountID)
		if err != nil {
			errChan <- err
			return
		}

		keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (types.SetupKey, error) {
			var sk types.SetupKey
			var autoGroups []byte
			var expiresAt, updatedAt, lastUsed sql.NullTime
			var revoked, ephemeral, allowExtraDNSLabels sql.NullBool
			var usedTimes, usageLimit sql.NullInt64

			err := row.Scan(&sk.Id, &sk.AccountID, &sk.Key, &sk.KeySecret, &sk.Name, &sk.Type, &sk.CreatedAt, &expiresAt, &updatedAt, &revoked, &usedTimes, &lastUsed, &autoGroups, &usageLimit, &ephemeral, &allowExtraDNSLabels)

			if err == nil {
				if expiresAt.Valid {
					sk.ExpiresAt = &expiresAt.Time
				}
				if updatedAt.Valid {
					sk.UpdatedAt = updatedAt.Time
					if sk.UpdatedAt.IsZero() {
						sk.UpdatedAt = sk.CreatedAt
					}
				}
				if lastUsed.Valid {
					sk.LastUsed = &lastUsed.Time
				}
				if revoked.Valid {
					sk.Revoked = revoked.Bool
				}
				if usedTimes.Valid {
					sk.UsedTimes = int(usedTimes.Int64)
				}
				if usageLimit.Valid {
					sk.UsageLimit = int(usageLimit.Int64)
				}
				if ephemeral.Valid {
					sk.Ephemeral = ephemeral.Bool
				}
				if allowExtraDNSLabels.Valid {
					sk.AllowExtraDNSLabels = allowExtraDNSLabels.Bool
				}
				if autoGroups != nil {
					_ = json.Unmarshal(autoGroups, &sk.AutoGroups)
				}
			}
			return sk, err
		})
		if err != nil {
			errChan <- err
			return
		}
		account.SetupKeysG = keys
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT id, account_id, key, ip, name, dns_label, user_id, ssh_key, ssh_enabled, login_expiration_enabled, inactivity_expiration_enabled, last_login, created_at, ephemeral, extra_dns_labels, allow_extra_dns_labels, meta_hostname, meta_go_os, meta_kernel, meta_core, meta_platform, meta_os, meta_os_version, meta_wt_version, meta_ui_version, meta_kernel_version, meta_network_addresses, meta_system_serial_number, meta_system_product_name, meta_system_manufacturer, meta_environment, meta_flags, meta_files, peer_status_last_seen, peer_status_connected, peer_status_login_expired, peer_status_requires_approval, location_connection_ip, location_country_code, location_city_name, location_geo_name_id FROM peers WHERE account_id = $1`
		rows, err := s.pool.Query(ctx, query, accountID)
		if err != nil {
			errChan <- err
			return
		}

		peers, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (nbpeer.Peer, error) {
			var p nbpeer.Peer
			p.Status = &nbpeer.PeerStatus{}
			var lastLogin sql.NullTime
			var sshEnabled, loginExpirationEnabled, inactivityExpirationEnabled, ephemeral, allowExtraDNSLabels sql.NullBool
			var peerStatusLastSeen sql.NullTime
			var peerStatusConnected, peerStatusLoginExpired, peerStatusRequiresApproval sql.NullBool
			var ip, extraDNS, netAddr, env, flags, files, connIP []byte

			err := row.Scan(&p.ID, &p.AccountID, &p.Key, &ip, &p.Name, &p.DNSLabel, &p.UserID, &p.SSHKey, &sshEnabled, &loginExpirationEnabled, &inactivityExpirationEnabled, &lastLogin, &p.CreatedAt, &ephemeral, &extraDNS, &allowExtraDNSLabels, &p.Meta.Hostname, &p.Meta.GoOS, &p.Meta.Kernel, &p.Meta.Core, &p.Meta.Platform, &p.Meta.OS, &p.Meta.OSVersion, &p.Meta.WtVersion, &p.Meta.UIVersion, &p.Meta.KernelVersion, &netAddr, &p.Meta.SystemSerialNumber, &p.Meta.SystemProductName, &p.Meta.SystemManufacturer, &env, &flags, &files, &peerStatusLastSeen, &peerStatusConnected, &peerStatusLoginExpired, &peerStatusRequiresApproval, &connIP, &p.Location.CountryCode, &p.Location.CityName, &p.Location.GeoNameID)

			if err == nil {
				if lastLogin.Valid {
					p.LastLogin = &lastLogin.Time
				}
				if sshEnabled.Valid {
					p.SSHEnabled = sshEnabled.Bool
				}
				if loginExpirationEnabled.Valid {
					p.LoginExpirationEnabled = loginExpirationEnabled.Bool
				}
				if inactivityExpirationEnabled.Valid {
					p.InactivityExpirationEnabled = inactivityExpirationEnabled.Bool
				}
				if ephemeral.Valid {
					p.Ephemeral = ephemeral.Bool
				}
				if allowExtraDNSLabels.Valid {
					p.AllowExtraDNSLabels = allowExtraDNSLabels.Bool
				}
				if peerStatusLastSeen.Valid {
					p.Status.LastSeen = peerStatusLastSeen.Time
				}
				if peerStatusConnected.Valid {
					p.Status.Connected = peerStatusConnected.Bool
				}
				if peerStatusLoginExpired.Valid {
					p.Status.LoginExpired = peerStatusLoginExpired.Bool
				}
				if peerStatusRequiresApproval.Valid {
					p.Status.RequiresApproval = peerStatusRequiresApproval.Bool
				}

				if ip != nil {
					_ = json.Unmarshal(ip, &p.IP)
				}
				if extraDNS != nil {
					_ = json.Unmarshal(extraDNS, &p.ExtraDNSLabels)
				}
				if netAddr != nil {
					_ = json.Unmarshal(netAddr, &p.Meta.NetworkAddresses)
				}
				if env != nil {
					_ = json.Unmarshal(env, &p.Meta.Environment)
				}
				if flags != nil {
					_ = json.Unmarshal(flags, &p.Meta.Flags)
				}
				if files != nil {
					_ = json.Unmarshal(files, &p.Meta.Files)
				}
				if connIP != nil {
					_ = json.Unmarshal(connIP, &p.Location.ConnectionIP)
				}
			}
			return p, err
		})
		if err != nil {
			errChan <- err
			return
		}
		account.PeersG = peers
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT id, account_id, role, is_service_user, non_deletable, service_user_name, auto_groups, blocked, pending_approval, last_login, created_at, issued, integration_ref_id, integration_ref_integration_type FROM users WHERE account_id = $1`
		rows, err := s.pool.Query(ctx, query, accountID)
		if err != nil {
			errChan <- err
			return
		}
		users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (types.User, error) {
			var u types.User
			var autoGroups []byte
			var lastLogin sql.NullTime
			var isServiceUser, nonDeletable, blocked, pendingApproval sql.NullBool
			err := row.Scan(&u.Id, &u.AccountID, &u.Role, &isServiceUser, &nonDeletable, &u.ServiceUserName, &autoGroups, &blocked, &pendingApproval, &lastLogin, &u.CreatedAt, &u.Issued, &u.IntegrationReference.ID, &u.IntegrationReference.IntegrationType)
			if err == nil {
				if lastLogin.Valid {
					u.LastLogin = &lastLogin.Time
				}
				if isServiceUser.Valid {
					u.IsServiceUser = isServiceUser.Bool
				}
				if nonDeletable.Valid {
					u.NonDeletable = nonDeletable.Bool
				}
				if blocked.Valid {
					u.Blocked = blocked.Bool
				}
				if pendingApproval.Valid {
					u.PendingApproval = pendingApproval.Bool
				}
				if autoGroups != nil {
					_ = json.Unmarshal(autoGroups, &u.AutoGroups)
				}
			}
			return u, err
		})
		if err != nil {
			errChan <- err
			return
		}
		account.UsersG = users
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT id, account_id, name, issued, resources, integration_ref_id, integration_ref_integration_type FROM groups WHERE account_id = $1`
		rows, err := s.pool.Query(ctx, query, accountID)
		if err != nil {
			errChan <- err
			return
		}
		groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*types.Group, error) {
			var g types.Group
			var resources []byte
			var refID sql.NullInt64
			var refType sql.NullString
			err := row.Scan(&g.ID, &g.AccountID, &g.Name, &g.Issued, &resources, &refID, &refType)
			if err == nil {
				if refID.Valid {
					g.IntegrationReference.ID = int(refID.Int64)
				}
				if refType.Valid {
					g.IntegrationReference.IntegrationType = refType.String
				}
				if resources != nil {
					_ = json.Unmarshal(resources, &g.Resources)
				}
			}
			return &g, err
		})
		if err != nil {
			errChan <- err
			return
		}
		account.GroupsG = groups
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT id, account_id, name, description, enabled, source_posture_checks FROM policies WHERE account_id = $1`
		rows, err := s.pool.Query(ctx, query, accountID)
		if err != nil {
			errChan <- err
			return
		}
		policies, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*types.Policy, error) {
			var p types.Policy
			var checks []byte
			var enabled sql.NullBool
			err := row.Scan(&p.ID, &p.AccountID, &p.Name, &p.Description, &enabled, &checks)
			if err == nil {
				if enabled.Valid {
					p.Enabled = enabled.Bool
				}
				if checks != nil {
					_ = json.Unmarshal(checks, &p.SourcePostureChecks)
				}
			}
			return &p, err
		})
		if err != nil {
			errChan <- err
			return
		}
		account.Policies = policies
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT id, account_id, network, domains, keep_route, net_id, description, peer, peer_groups, network_type, masquerade, metric, enabled, groups, access_control_groups, skip_auto_apply FROM routes WHERE account_id = $1`
		rows, err := s.pool.Query(ctx, query, accountID)
		if err != nil {
			errChan <- err
			return
		}
		routes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (route.Route, error) {
			var r route.Route
			var network, domains, peerGroups, groups, accessGroups []byte
			var keepRoute, masquerade, enabled, skipAutoApply sql.NullBool
			var metric sql.NullInt64
			err := row.Scan(&r.ID, &r.AccountID, &network, &domains, &keepRoute, &r.NetID, &r.Description, &r.Peer, &peerGroups, &r.NetworkType, &masquerade, &metric, &enabled, &groups, &accessGroups, &skipAutoApply)
			if err == nil {
				if keepRoute.Valid {
					r.KeepRoute = keepRoute.Bool
				}
				if masquerade.Valid {
					r.Masquerade = masquerade.Bool
				}
				if enabled.Valid {
					r.Enabled = enabled.Bool
				}
				if skipAutoApply.Valid {
					r.SkipAutoApply = skipAutoApply.Bool
				}
				if metric.Valid {
					r.Metric = int(metric.Int64)
				}
				if network != nil {
					_ = json.Unmarshal(network, &r.Network)
				}
				if domains != nil {
					_ = json.Unmarshal(domains, &r.Domains)
				}
				if peerGroups != nil {
					_ = json.Unmarshal(peerGroups, &r.PeerGroups)
				}
				if groups != nil {
					_ = json.Unmarshal(groups, &r.Groups)
				}
				if accessGroups != nil {
					_ = json.Unmarshal(accessGroups, &r.AccessControlGroups)
				}
			}
			return r, err
		})
		if err != nil {
			errChan <- err
			return
		}
		account.RoutesG = routes
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT id, account_id, name, description, name_servers, groups, "primary", domains, enabled, search_domains_enabled FROM name_server_groups WHERE account_id = $1`
		rows, err := s.pool.Query(ctx, query, accountID)
		if err != nil {
			errChan <- err
			return
		}
		nsgs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (nbdns.NameServerGroup, error) {
			var n nbdns.NameServerGroup
			var ns, groups, domains []byte
			var primary, enabled, searchDomainsEnabled sql.NullBool
			err := row.Scan(&n.ID, &n.AccountID, &n.Name, &n.Description, &ns, &groups, &primary, &domains, &enabled, &searchDomainsEnabled)
			if err == nil {
				if primary.Valid {
					n.Primary = primary.Bool
				}
				if enabled.Valid {
					n.Enabled = enabled.Bool
				}
				if searchDomainsEnabled.Valid {
					n.SearchDomainsEnabled = searchDomainsEnabled.Bool
				}
				if ns != nil {
					_ = json.Unmarshal(ns, &n.NameServers)
				}
				if groups != nil {
					_ = json.Unmarshal(groups, &n.Groups)
				}
				if domains != nil {
					_ = json.Unmarshal(domains, &n.Domains)
				}
			}
			return n, err
		})
		if err != nil {
			errChan <- err
			return
		}
		account.NameServerGroupsG = nsgs
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT id, account_id, name, description, checks FROM posture_checks WHERE account_id = $1`
		rows, err := s.pool.Query(ctx, query, accountID)
		if err != nil {
			errChan <- err
			return
		}
		checks, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*posture.Checks, error) {
			var c posture.Checks
			var checksDef []byte
			err := row.Scan(&c.ID, &c.AccountID, &c.Name, &c.Description, &checksDef)
			if err == nil && checksDef != nil {
				_ = json.Unmarshal(checksDef, &c.Checks)
			}
			return &c, err
		})
		if err != nil {
			errChan <- err
			return
		}
		account.PostureChecks = checks
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT id, account_id, name, description FROM networks WHERE account_id = $1`
		rows, err := s.pool.Query(ctx, query, accountID)
		if err != nil {
			errChan <- err
			return
		}
		networks, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkTypes.Network])
		if err != nil {
			errChan <- err
			return
		}
		account.Networks = make([]*networkTypes.Network, len(networks))
		for i := range networks {
			account.Networks[i] = &networks[i]
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT id, network_id, account_id, peer, peer_groups, masquerade, metric, enabled FROM network_routers WHERE account_id = $1`
		rows, err := s.pool.Query(ctx, query, accountID)
		if err != nil {
			errChan <- err
			return
		}
		routers, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (routerTypes.NetworkRouter, error) {
			var r routerTypes.NetworkRouter
			var peerGroups []byte
			var masquerade, enabled sql.NullBool
			var metric sql.NullInt64
			err := row.Scan(&r.ID, &r.NetworkID, &r.AccountID, &r.Peer, &peerGroups, &masquerade, &metric, &enabled)
			if err == nil {
				if masquerade.Valid {
					r.Masquerade = masquerade.Bool
				}
				if enabled.Valid {
					r.Enabled = enabled.Bool
				}
				if metric.Valid {
					r.Metric = int(metric.Int64)
				}
				if peerGroups != nil {
					_ = json.Unmarshal(peerGroups, &r.PeerGroups)
				}
			}
			return r, err
		})
		if err != nil {
			errChan <- err
			return
		}
		account.NetworkRouters = make([]*routerTypes.NetworkRouter, len(routers))
		for i := range routers {
			account.NetworkRouters[i] = &routers[i]
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT id, network_id, account_id, name, description, type, domain, prefix, enabled FROM network_resources WHERE account_id = $1`
		rows, err := s.pool.Query(ctx, query, accountID)
		if err != nil {
			errChan <- err
			return
		}
		resources, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (resourceTypes.NetworkResource, error) {
			var r resourceTypes.NetworkResource
			var prefix []byte
			var enabled sql.NullBool
			err := row.Scan(&r.ID, &r.NetworkID, &r.AccountID, &r.Name, &r.Description, &r.Type, &r.Domain, &prefix, &enabled)
			if err == nil {
				if enabled.Valid {
					r.Enabled = enabled.Bool
				}
				if prefix != nil {
					_ = json.Unmarshal(prefix, &r.Prefix)
				}
			}
			return r, err
		})
		if err != nil {
			errChan <- err
			return
		}
		account.NetworkResources = make([]*resourceTypes.NetworkResource, len(resources))
		for i := range resources {
			account.NetworkResources[i] = &resources[i]
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		const query = `SELECT account_id, onboarding_flow_pending, signup_form_pending, created_at, updated_at FROM account_onboardings WHERE account_id = $1`
		var onboardingFlowPending, signupFormPending sql.NullBool
		err := s.pool.QueryRow(ctx, query, accountID).Scan(
			&account.Onboarding.AccountID,
			&onboardingFlowPending,
			&signupFormPending,
			&account.Onboarding.CreatedAt,
			&account.Onboarding.UpdatedAt,
		)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			errChan <- err
			return
		}
		if onboardingFlowPending.Valid {
			account.Onboarding.OnboardingFlowPending = onboardingFlowPending.Bool
		}
		if signupFormPending.Valid {
			account.Onboarding.SignupFormPending = signupFormPending.Bool
		}
	}()

	wg.Wait()
	close(errChan)
	for e := range errChan {
		if e != nil {
			return nil, e
		}
	}

	var userIDs []string
	for _, u := range account.UsersG {
		userIDs = append(userIDs, u.Id)
	}
	var policyIDs []string
	for _, p := range account.Policies {
		policyIDs = append(policyIDs, p.ID)
	}
	var groupIDs []string
	for _, g := range account.GroupsG {
		groupIDs = append(groupIDs, g.ID)
	}

	wg.Add(3)
	errChan = make(chan error, 3)

	var pats []types.PersonalAccessToken
	go func() {
		defer wg.Done()
		if len(userIDs) == 0 {
			return
		}
		const query = `SELECT id, user_id, name, hashed_token, expiration_date, created_by, created_at, last_used FROM personal_access_tokens WHERE user_id = ANY($1)`
		rows, err := s.pool.Query(ctx, query, userIDs)
		if err != nil {
			errChan <- err
			return
		}
		pats, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (types.PersonalAccessToken, error) {
			var pat types.PersonalAccessToken
			var expirationDate, lastUsed sql.NullTime
			err := row.Scan(&pat.ID, &pat.UserID, &pat.Name, &pat.HashedToken, &expirationDate, &pat.CreatedBy, &pat.CreatedAt, &lastUsed)
			if err == nil {
				if expirationDate.Valid {
					pat.ExpirationDate = &expirationDate.Time
				}
				if lastUsed.Valid {
					pat.LastUsed = &lastUsed.Time
				}
			}
			return pat, err
		})
		if err != nil {
			errChan <- err
		}
	}()

	var rules []*types.PolicyRule
	go func() {
		defer wg.Done()
		if len(policyIDs) == 0 {
			return
		}
		const query = `SELECT id, policy_id, name, description, enabled, action, destinations, destination_resource, sources, source_resource, bidirectional, protocol, ports, port_ranges FROM policy_rules WHERE policy_id = ANY($1)`
		rows, err := s.pool.Query(ctx, query, policyIDs)
		if err != nil {
			errChan <- err
			return
		}
		rules, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (*types.PolicyRule, error) {
			var r types.PolicyRule
			var dest, destRes, sources, sourceRes, ports, portRanges []byte
			var enabled, bidirectional sql.NullBool
			err := row.Scan(&r.ID, &r.PolicyID, &r.Name, &r.Description, &enabled, &r.Action, &dest, &destRes, &sources, &sourceRes, &bidirectional, &r.Protocol, &ports, &portRanges)
			if err == nil {
				if enabled.Valid {
					r.Enabled = enabled.Bool
				}
				if bidirectional.Valid {
					r.Bidirectional = bidirectional.Bool
				}
				if dest != nil {
					_ = json.Unmarshal(dest, &r.Destinations)
				}
				if destRes != nil {
					_ = json.Unmarshal(destRes, &r.DestinationResource)
				}
				if sources != nil {
					_ = json.Unmarshal(sources, &r.Sources)
				}
				if sourceRes != nil {
					_ = json.Unmarshal(sourceRes, &r.SourceResource)
				}
				if ports != nil {
					_ = json.Unmarshal(ports, &r.Ports)
				}
				if portRanges != nil {
					_ = json.Unmarshal(portRanges, &r.PortRanges)
				}
			}
			return &r, err
		})
		if err != nil {
			errChan <- err
		}
	}()

	var groupPeers []types.GroupPeer
	go func() {
		defer wg.Done()
		if len(groupIDs) == 0 {
			return
		}
		const query = `SELECT account_id, group_id, peer_id FROM group_peers WHERE group_id = ANY($1)`
		rows, err := s.pool.Query(ctx, query, groupIDs)
		if err != nil {
			errChan <- err
			return
		}
		groupPeers, err = pgx.CollectRows(rows, pgx.RowToStructByName[types.GroupPeer])
		if err != nil {
			errChan <- err
		}
	}()

	wg.Wait()
	close(errChan)
	for e := range errChan {
		if e != nil {
			return nil, e
		}
	}

	patsByUserID := make(map[string][]*types.PersonalAccessToken)
	for i := range pats {
		pat := &pats[i]
		patsByUserID[pat.UserID] = append(patsByUserID[pat.UserID], pat)
		pat.UserID = ""
	}

	rulesByPolicyID := make(map[string][]*types.PolicyRule)
	for _, rule := range rules {
		rulesByPolicyID[rule.PolicyID] = append(rulesByPolicyID[rule.PolicyID], rule)
	}

	peersByGroupID := make(map[string][]string)
	for _, gp := range groupPeers {
		peersByGroupID[gp.GroupID] = append(peersByGroupID[gp.GroupID], gp.PeerID)
	}

	account.SetupKeys = make(map[string]*types.SetupKey, len(account.SetupKeysG))
	for i := range account.SetupKeysG {
		key := &account.SetupKeysG[i]
		account.SetupKeys[key.Key] = key
	}

	account.Peers = make(map[string]*nbpeer.Peer, len(account.PeersG))
	for i := range account.PeersG {
		peer := &account.PeersG[i]
		account.Peers[peer.ID] = peer
	}

	account.Users = make(map[string]*types.User, len(account.UsersG))
	for i := range account.UsersG {
		user := &account.UsersG[i]
		user.PATs = make(map[string]*types.PersonalAccessToken)
		if userPats, ok := patsByUserID[user.Id]; ok {
			for j := range userPats {
				pat := userPats[j]
				user.PATs[pat.ID] = pat
			}
		}
		account.Users[user.Id] = user
	}

	for i := range account.Policies {
		policy := account.Policies[i]
		if policyRules, ok := rulesByPolicyID[policy.ID]; ok {
			policy.Rules = policyRules
		}
	}

	account.Groups = make(map[string]*types.Group, len(account.GroupsG))
	for i := range account.GroupsG {
		group := account.GroupsG[i]
		if peerIDs, ok := peersByGroupID[group.ID]; ok {
			group.Peers = peerIDs
		}
		account.Groups[group.ID] = group
	}

	account.Routes = make(map[route.ID]*route.Route, len(account.RoutesG))
	for i := range account.RoutesG {
		route := &account.RoutesG[i]
		account.Routes[route.ID] = route
	}

	account.NameServerGroups = make(map[string]*nbdns.NameServerGroup, len(account.NameServerGroupsG))
	for i := range account.NameServerGroupsG {
		nsg := &account.NameServerGroupsG[i]
		nsg.AccountID = ""
		account.NameServerGroups[nsg.ID] = nsg
	}

	account.SetupKeysG = nil
	account.PeersG = nil
	account.UsersG = nil
	account.GroupsG = nil
	account.RoutesG = nil
	account.NameServerGroupsG = nil

	return &account, nil
}
