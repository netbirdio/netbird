package store

import (
	"context"
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

	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
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
		Preload("UsersG.PATsG"). // have to be specified as this is nested reference
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

func (s *SqlStore) GetAccountGormOpt(ctx context.Context, accountID string) (*types.Account, error) {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		if elapsed > 1*time.Second {
			log.WithContext(ctx).Tracef("GetAccount for account %s exceeded 1s, took: %v", accountID, elapsed)
		}
	}()

	var account types.Account
	result := s.db.Model(&account).
		Preload("UsersG.PATsG"). // have to be specified as this is nested reference
		Preload("Policies.Rules").
		Preload("SetupKeysG").
		Preload("PeersG").
		Preload("UsersG").
		Preload("GroupsG.GroupPeers").
		Preload("RoutesG").
		Preload("NameServerGroupsG").
		Preload("PostureChecks").
		Preload("Networks").
		Preload("NetworkRouters").
		Preload("NetworkResources").
		Preload("Onboarding").
		Take(&account, idQueryCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("error when getting account %s from the store: %s", accountID, result.Error)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		return nil, status.NewGetAccountFromStoreError(result.Error)
	}

	account.SetupKeys = make(map[string]*types.SetupKey, len(account.SetupKeysG))
	for _, key := range account.SetupKeysG {
		if key.UpdatedAt.IsZero() {
			key.UpdatedAt = key.CreatedAt
		}
		if key.AutoGroups == nil {
			key.AutoGroups = []string{}
		}
		account.SetupKeys[key.Key] = &key
	}
	account.SetupKeysG = nil

	account.Peers = make(map[string]*nbpeer.Peer, len(account.PeersG))
	for _, peer := range account.PeersG {
		account.Peers[peer.ID] = &peer
	}
	account.PeersG = nil
	account.Users = make(map[string]*types.User, len(account.UsersG))
	for _, user := range account.UsersG {
		user.PATs = make(map[string]*types.PersonalAccessToken, len(user.PATs))
		for _, pat := range user.PATsG {
			pat.UserID = ""
			user.PATs[pat.ID] = &pat
		}
		if user.AutoGroups == nil {
			user.AutoGroups = []string{}
		}
		account.Users[user.Id] = &user
		user.PATsG = nil
	}
	account.UsersG = nil
	account.Groups = make(map[string]*types.Group, len(account.GroupsG))
	for _, group := range account.GroupsG {
		group.Peers = make([]string, len(group.GroupPeers))
		for i, gp := range group.GroupPeers {
			group.Peers[i] = gp.PeerID
		}
		if group.Resources == nil {
			group.Resources = []types.Resource{}
		}
		account.Groups[group.ID] = group
	}
	account.GroupsG = nil

	account.Routes = make(map[route.ID]*route.Route, len(account.RoutesG))
	for _, route := range account.RoutesG {
		account.Routes[route.ID] = &route
	}
	account.RoutesG = nil
	account.NameServerGroups = make(map[string]*nbdns.NameServerGroup, len(account.NameServerGroupsG))
	for _, ns := range account.NameServerGroupsG {
		ns.AccountID = ""
		if ns.NameServers == nil {
			ns.NameServers = []nbdns.NameServer{}
		}
		if ns.Groups == nil {
			ns.Groups = []string{}
		}
		if ns.Domains == nil {
			ns.Domains = []string{}
		}
		account.NameServerGroups[ns.ID] = &ns
	}
	account.NameServerGroupsG = nil
	return &account, nil
}

func connectDBforTest(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database config: %w", err)
	}

	config.MaxConns = 12
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
	return pool, nil
}

func setupBenchmarkDB(b testing.TB) (*SqlStore, func(), string) {
	cleanup, dsn, err := testutil.CreatePostgresTestContainer()
	if err != nil {
		b.Fatalf("failed to create test container: %v", err)
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		b.Fatalf("failed to connect database: %v", err)
	}

	pool, err := connectDBforTest(context.Background(), dsn)
	if err != nil {
		b.Fatalf("failed to connect database: %v", err)
	}

	models := []interface{}{
		&types.Account{}, &types.SetupKey{}, &nbpeer.Peer{}, &types.User{},
		&types.PersonalAccessToken{}, &types.Group{}, &types.GroupPeer{},
		&types.Policy{}, &types.PolicyRule{}, &route.Route{},
		&nbdns.NameServerGroup{}, &posture.Checks{}, &networkTypes.Network{},
		&routerTypes.NetworkRouter{}, &resourceTypes.NetworkResource{},
		&types.AccountOnboarding{}, &reverseproxy.Service{}, &reverseproxy.Target{},
	}

	for i := len(models) - 1; i >= 0; i-- {
		err := db.Migrator().DropTable(models[i])
		if err != nil {
			b.Fatalf("failed to drop table: %v", err)
		}
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

	return store, cleanup, accountID
}

func BenchmarkGetAccount(b *testing.B) {
	store, cleanup, accountID := setupBenchmarkDB(b)
	defer cleanup()
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
	b.Run("gorm opt", func(b *testing.B) {
		for range b.N {
			_, err := store.GetAccountGormOpt(ctx, accountID)
			if err != nil {
				b.Fatalf("GetAccountFast failed: %v", err)
			}
		}
	})
	b.Run("raw", func(b *testing.B) {
		for range b.N {
			_, err := store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("GetAccountPureSQL failed: %v", err)
			}
		}
	})
	store.pool.Close()
}

func TestAccountEquivalence(t *testing.T) {
	store, cleanup, accountID := setupBenchmarkDB(t)
	defer cleanup()
	ctx := context.Background()

	type getAccountFunc func(context.Context, string) (*types.Account, error)

	tests := []struct {
		name      string
		expectedF getAccountFunc
		actualF   getAccountFunc
	}{
		{"old vs new", store.GetAccountSlow, store.GetAccountGormOpt},
		{"old vs raw", store.GetAccountSlow, store.GetAccount},
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

func (s *SqlStore) GetAccountPureSQL(ctx context.Context, accountID string) (*types.Account, error) {
	account, err := s.getAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 12)

	wg.Add(1)
	go func() {
		defer wg.Done()
		keys, err := s.getSetupKeys(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.SetupKeysG = keys
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		peers, err := s.getPeers(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.PeersG = peers
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		users, err := s.getUsers(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.UsersG = users
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		groups, err := s.getGroups(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.GroupsG = groups
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		policies, err := s.getPolicies(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.Policies = policies
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		routes, err := s.getRoutes(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.RoutesG = routes
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		nsgs, err := s.getNameServerGroups(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.NameServerGroupsG = nsgs
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		checks, err := s.getPostureChecks(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.PostureChecks = checks
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		networks, err := s.getNetworks(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.Networks = networks
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		routers, err := s.getNetworkRouters(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.NetworkRouters = routers
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		resources, err := s.getNetworkResources(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.NetworkResources = resources
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := s.getAccountOnboarding(ctx, accountID, account)
		if err != nil {
			errChan <- err
			return
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
		var err error
		pats, err = s.getPersonalAccessTokens(ctx, userIDs)
		if err != nil {
			errChan <- err
		}
	}()

	var rules []*types.PolicyRule
	go func() {
		defer wg.Done()
		var err error
		rules, err = s.getPolicyRules(ctx, policyIDs)
		if err != nil {
			errChan <- err
		}
	}()

	var groupPeers []types.GroupPeer
	go func() {
		defer wg.Done()
		var err error
		groupPeers, err = s.getGroupPeers(ctx, groupIDs)
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

	return account, nil
}
