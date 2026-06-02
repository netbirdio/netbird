package store

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

var errRollback = errors.New("intentional rollback")

func TestAllocateAccountSeqID_SequentialPerAccount(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	ctx := context.Background()
	const accA = "acc-a"
	const accB = "acc-b"

	require.NoError(t, store.ExecuteInTransaction(ctx, func(tx Store) error {
		got, err := tx.AllocateAccountSeqID(ctx, accA, types.AccountSeqEntityPolicy)
		require.NoError(t, err)
		require.Equal(t, uint32(1), got)

		got, err = tx.AllocateAccountSeqID(ctx, accA, types.AccountSeqEntityPolicy)
		require.NoError(t, err)
		require.Equal(t, uint32(2), got)

		got, err = tx.AllocateAccountSeqID(ctx, accB, types.AccountSeqEntityPolicy)
		require.NoError(t, err)
		require.Equal(t, uint32(1), got, "different account starts from 1")

		got, err = tx.AllocateAccountSeqID(ctx, accA, types.AccountSeqEntityGroup)
		require.NoError(t, err)
		require.Equal(t, uint32(1), got, "different entity starts from 1")

		return nil
	}))

	require.NoError(t, store.ExecuteInTransaction(ctx, func(tx Store) error {
		got, err := tx.AllocateAccountSeqID(ctx, accA, types.AccountSeqEntityPolicy)
		require.NoError(t, err)
		require.Equal(t, uint32(3), got, "counter persists across transactions")
		return nil
	}))
}

func TestPolicyBackfill_AssignsSeqIDsToExistingPolicies(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	ctx := context.Background()
	const accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	policies, err := store.GetAccountPolicies(ctx, LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.NotEmpty(t, policies, "test fixture must have policies")

	seen := make(map[uint32]bool)
	for _, p := range policies {
		require.NotZero(t, p.AccountSeqID, "policy %s must have a non-zero AccountSeqID after migration", p.ID)
		require.False(t, seen[p.AccountSeqID], "duplicate AccountSeqID %d in account %s", p.AccountSeqID, accountID)
		seen[p.AccountSeqID] = true
	}
}

func TestPolicyUpdate_PreservesSeqID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	ctx := context.Background()
	const accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	const policyID = "cs1tnh0hhcjnqoiuebf0"

	original, err := store.GetPolicyByID(ctx, LockingStrengthNone, accountID, policyID)
	require.NoError(t, err)
	originalSeq := original.AccountSeqID
	require.NotZero(t, originalSeq, "fixture must have non-zero AccountSeqID after backfill")

	updated := &types.Policy{
		ID:        policyID,
		AccountID: accountID,
		Name:      "renamed",
		Enabled:   false,
		Rules:     original.Rules,
	}
	require.Zero(t, updated.AccountSeqID, "incoming struct should have zero AccountSeqID like an HTTP handler would")

	require.NoError(t, store.SavePolicy(ctx, updated))

	got, err := store.GetPolicyByID(ctx, LockingStrengthNone, accountID, policyID)
	require.NoError(t, err)
	require.Equal(t, originalSeq, got.AccountSeqID, "AccountSeqID must not be reset by update path")
	require.Equal(t, "renamed", got.Name)
}

func TestGroupUpdate_PreservesSeqID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	ctx := context.Background()
	const accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	groups, err := store.GetAccountGroups(ctx, LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.NotEmpty(t, groups)

	original := groups[0]
	originalSeq := original.AccountSeqID
	require.NotZero(t, originalSeq)

	updated := &types.Group{
		ID:        original.ID,
		AccountID: accountID,
		Name:      "renamed",
		Issued:    original.Issued,
	}
	require.Zero(t, updated.AccountSeqID)

	require.NoError(t, store.UpdateGroup(ctx, updated))

	got, err := store.GetGroupByID(ctx, LockingStrengthNone, accountID, original.ID)
	require.NoError(t, err)
	require.Equal(t, originalSeq, got.AccountSeqID, "AccountSeqID must not be reset by UpdateGroup")
	require.Equal(t, "renamed", got.Name)
}

func TestSaveAccount_AllocatesSeqIDsForDefaultGroupAndPolicy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	ctx := context.Background()
	const accountID = "save-account-seqid-test"

	account := &types.Account{
		Id:          accountID,
		CreatedBy:   "user1",
		Domain:      "example.test",
		DNSSettings: types.DNSSettings{},
		Settings:    &types.Settings{},
		Network: &types.Network{
			Identifier: "net-test",
		},
		Users: map[string]*types.User{
			"user1": {Id: "user1", AccountID: accountID, Role: types.UserRoleOwner},
		},
	}
	require.NoError(t, account.AddAllGroup(false), "AddAllGroup should populate default Group + Policy")
	require.Len(t, account.Groups, 1, "default 'All' group must be present")
	require.Len(t, account.Policies, 1, "default policy must be present")

	for _, g := range account.Groups {
		require.Zero(t, g.AccountSeqID, "default group must start with seq=0")
	}
	require.Zero(t, account.Policies[0].AccountSeqID, "default policy must start with seq=0")

	require.NoError(t, store.SaveAccount(ctx, account))

	groups, err := store.GetAccountGroups(ctx, LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.NotZerof(t, groups[0].AccountSeqID, "default group must have seq>0 after SaveAccount")

	policies, err := store.GetAccountPolicies(ctx, LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotZerof(t, policies[0].AccountSeqID, "default policy must have seq>0 after SaveAccount")

	require.ErrorIs(t, store.ExecuteInTransaction(ctx, func(tx Store) error {
		next, err := tx.AllocateAccountSeqID(ctx, accountID, types.AccountSeqEntityGroup)
		require.NoError(t, err)
		require.Equal(t, groups[0].AccountSeqID+1, next, "next group seq must be max+1")

		next, err = tx.AllocateAccountSeqID(ctx, accountID, types.AccountSeqEntityPolicy)
		require.NoError(t, err)
		require.Equal(t, policies[0].AccountSeqID+1, next, "next policy seq must be max+1")
		return errRollback
	}), errRollback)
}

func TestSaveAccount_PreservesExistingSeqIDs(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	ctx := context.Background()
	const accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	account, err := store.GetAccount(ctx, accountID)
	require.NoError(t, err)

	groupSeqs := make(map[string]uint32)
	policySeqs := make(map[string]uint32)
	routeSeqs := make(map[route.ID]uint32)
	nsgSeqs := make(map[string]uint32)
	resourceSeqs := make(map[string]uint32)
	routerSeqs := make(map[string]uint32)
	networkSeqs := make(map[string]uint32)

	for _, g := range account.Groups {
		require.NotZero(t, g.AccountSeqID, "fixture group must have seq>0 after backfill")
		groupSeqs[g.ID] = g.AccountSeqID
	}
	for _, p := range account.Policies {
		require.NotZero(t, p.AccountSeqID, "fixture policy must have seq>0")
		policySeqs[p.ID] = p.AccountSeqID
	}
	for _, r := range account.Routes {
		require.NotZero(t, r.AccountSeqID, "fixture route must have seq>0")
		routeSeqs[r.ID] = r.AccountSeqID
	}
	for _, n := range account.NameServerGroups {
		require.NotZero(t, n.AccountSeqID, "fixture name_server_group must have seq>0")
		nsgSeqs[n.ID] = n.AccountSeqID
	}
	for _, nr := range account.NetworkResources {
		require.NotZero(t, nr.AccountSeqID, "fixture network_resource must have seq>0")
		resourceSeqs[nr.ID] = nr.AccountSeqID
	}
	for _, nr := range account.NetworkRouters {
		require.NotZero(t, nr.AccountSeqID, "fixture network_router must have seq>0")
		routerSeqs[nr.ID] = nr.AccountSeqID
	}
	for _, n := range account.Networks {
		require.NotZero(t, n.AccountSeqID, "fixture network must have seq>0 after backfill")
		networkSeqs[n.ID] = n.AccountSeqID
	}

	require.NoError(t, store.SaveAccount(ctx, account))

	after, err := store.GetAccount(ctx, accountID)
	require.NoError(t, err)
	for _, g := range after.Groups {
		require.Equal(t, groupSeqs[g.ID], g.AccountSeqID, "group %s seq must be preserved on re-save", g.ID)
	}
	for _, p := range after.Policies {
		require.Equal(t, policySeqs[p.ID], p.AccountSeqID, "policy %s seq must be preserved", p.ID)
	}
	for _, r := range after.Routes {
		require.Equal(t, routeSeqs[r.ID], r.AccountSeqID, "route %s seq must be preserved (slice-of-value addressability)", r.ID)
	}
	for _, n := range after.NameServerGroups {
		require.Equal(t, nsgSeqs[n.ID], n.AccountSeqID, "name_server_group %s seq must be preserved (slice-of-value addressability)", n.ID)
	}
	for _, nr := range after.NetworkResources {
		require.Equal(t, resourceSeqs[nr.ID], nr.AccountSeqID, "network_resource %s seq must be preserved", nr.ID)
	}
	for _, nr := range after.NetworkRouters {
		require.Equal(t, routerSeqs[nr.ID], nr.AccountSeqID, "network_router %s seq must be preserved", nr.ID)
	}
	for _, n := range after.Networks {
		require.Equal(t, networkSeqs[n.ID], n.AccountSeqID, "network %s seq must be preserved", n.ID)
	}
}

func TestSaveAccount_AllocatesSeqIDsForAllEntityTypes(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	ctx := context.Background()
	const accountID = "save-account-all-entities"

	addr, err := netip.ParseAddr("8.8.8.8")
	require.NoError(t, err)

	account := &types.Account{
		Id:        accountID,
		CreatedBy: "user1",
		Domain:    "example.test",
		Settings:  &types.Settings{},
		Network:   &types.Network{Identifier: "net-test"},
		Users: map[string]*types.User{
			"user1": {Id: "user1", AccountID: accountID, Role: types.UserRoleOwner},
		},
		Groups: map[string]*types.Group{
			"g1": {ID: "g1", AccountID: accountID, Name: "g1", Issued: types.GroupIssuedAPI},
		},
		Policies: []*types.Policy{
			{ID: "p1", AccountID: accountID, Name: "p1", Enabled: true,
				Rules: []*types.PolicyRule{{ID: "r1", PolicyID: "p1", Enabled: true}}},
		},
		Routes: map[route.ID]*route.Route{
			"rt1": {ID: "rt1", AccountID: accountID, NetID: "net1", Peer: "peer1"},
		},
		NameServerGroups: map[string]*nbdns.NameServerGroup{
			"nsg1": {ID: "nsg1", AccountID: accountID, Name: "nsg1", Enabled: true,
				NameServers: []nbdns.NameServer{{IP: addr, NSType: nbdns.UDPNameServerType, Port: 53}}},
		},
		NetworkResources: []*resourceTypes.NetworkResource{
			{ID: "nr1", AccountID: accountID, NetworkID: "net1", Name: "res1", Enabled: true},
		},
		NetworkRouters: []*routerTypes.NetworkRouter{
			{ID: "nrt1", AccountID: accountID, NetworkID: "net1", Peer: "peer1", Enabled: true},
		},
		Networks: []*networkTypes.Network{
			{ID: "n1", AccountID: accountID, Name: "n1"},
		},
		PostureChecks: []*posture.Checks{
			{ID: "pc1", AccountID: accountID, Name: "pc1",
				Checks: posture.ChecksDefinition{
					NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.26.0"},
				}},
		},
	}

	require.NoError(t, store.SaveAccount(ctx, account))

	after, err := store.GetAccount(ctx, accountID)
	require.NoError(t, err)

	require.Len(t, after.Groups, 1)
	require.Len(t, after.Policies, 1)
	require.Len(t, after.Routes, 1)
	require.Len(t, after.NameServerGroups, 1)
	require.Len(t, after.NetworkResources, 1)
	require.Len(t, after.NetworkRouters, 1)
	require.Len(t, after.Networks, 1)
	require.Len(t, after.PostureChecks, 1)

	for _, g := range after.Groups {
		require.NotZero(t, g.AccountSeqID, "group seq must be allocated")
	}
	for _, p := range after.Policies {
		require.NotZero(t, p.AccountSeqID, "policy seq must be allocated")
	}
	for _, r := range after.Routes {
		require.NotZero(t, r.AccountSeqID, "route seq must be allocated (slice-of-value addressability)")
	}
	for _, n := range after.NameServerGroups {
		require.NotZero(t, n.AccountSeqID, "name_server_group seq must be allocated (slice-of-value addressability)")
	}
	for _, nr := range after.NetworkResources {
		require.NotZero(t, nr.AccountSeqID, "network_resource seq must be allocated")
	}
	for _, nr := range after.NetworkRouters {
		require.NotZero(t, nr.AccountSeqID, "network_router seq must be allocated")
	}
	for _, n := range after.Networks {
		require.NotZero(t, n.AccountSeqID, "network seq must be allocated")
	}
	for _, pc := range after.PostureChecks {
		require.NotZero(t, pc.AccountSeqID, "posture_check seq must be allocated")
	}

	require.NoError(t, store.SaveAccount(ctx, after))
	final, err := store.GetAccount(ctx, accountID)
	require.NoError(t, err)
	for _, r := range final.Routes {
		require.Equal(t, after.Routes[r.ID].AccountSeqID, r.AccountSeqID, "route seq preserved on re-save")
	}
	for _, n := range final.NameServerGroups {
		require.Equal(t, after.NameServerGroups[n.ID].AccountSeqID, n.AccountSeqID, "name_server_group seq preserved on re-save")
	}
	afterByID := map[string]uint32{}
	for _, n := range after.Networks {
		afterByID[n.ID] = n.AccountSeqID
	}
	for _, n := range final.Networks {
		require.Equal(t, afterByID[n.ID], n.AccountSeqID, "network seq preserved on re-save")
	}
	afterPCByID := map[string]uint32{}
	for _, pc := range after.PostureChecks {
		afterPCByID[pc.ID] = pc.AccountSeqID
	}
	for _, pc := range final.PostureChecks {
		require.Equal(t, afterPCByID[pc.ID], pc.AccountSeqID, "posture_check seq preserved on re-save")
	}
}

func TestAllocateAccountSeqID_ConcurrentSameAccountEntity(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	ctx := context.Background()
	const accountID = "concurrent-test"
	const entity = types.AccountSeqEntityPolicy
	const goroutines = 32

	type result struct {
		seq uint32
		err error
	}
	results := make(chan result, goroutines)
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		go func() {
			<-start
			var allocated uint32
			err := store.ExecuteInTransaction(ctx, func(tx Store) error {
				seq, err := tx.AllocateAccountSeqID(ctx, accountID, entity)
				allocated = seq
				return err
			})
			results <- result{seq: allocated, err: err}
		}()
	}
	close(start)

	seen := make(map[uint32]int, goroutines)
	for i := 0; i < goroutines; i++ {
		r := <-results
		require.NoError(t, r.err, "concurrent allocate must not fail")
		require.NotZero(t, r.seq, "allocated seq must be non-zero")
		seen[r.seq]++
	}

	require.Lenf(t, seen, goroutines, "every concurrent allocation must yield a unique id; got duplicates in %v", seen)
	for i := uint32(1); i <= goroutines; i++ {
		require.Equalf(t, 1, seen[i], "id %d must appear exactly once across concurrent allocations", i)
	}
}

func TestStoreCreateGroups_AllocatedSeqIDIsNotClobbered(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	ctx := context.Background()
	const accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	groups := []*types.Group{
		{ID: "seq-test-g1", AccountID: accountID, Name: "g1", Issued: "jwt", AccountSeqID: 7777},
		{ID: "seq-test-g2", AccountID: accountID, Name: "g2", Issued: "jwt", AccountSeqID: 7778},
	}
	require.NoError(t, store.CreateGroups(ctx, accountID, groups))

	for _, want := range groups {
		got, err := store.GetGroupByID(ctx, LockingStrengthNone, accountID, want.ID)
		require.NoError(t, err)
		require.Equal(t, want.AccountSeqID, got.AccountSeqID, "seq id from caller must be persisted on insert")
	}

	groups[0].Name = "g1-renamed"
	groups[0].AccountSeqID = 0
	require.NoError(t, store.CreateGroups(ctx, accountID, groups[:1]))

	got, err := store.GetGroupByID(ctx, LockingStrengthNone, accountID, "seq-test-g1")
	require.NoError(t, err)
	require.Equal(t, "g1-renamed", got.Name, "upsert path still updates other columns")
	require.Equal(t, uint32(7777), got.AccountSeqID, "upsert path must NOT overwrite account_seq_id")
}

func TestPolicyCreate_AllocatesSeqID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	ctx := context.Background()
	const accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	existing, err := store.GetAccountPolicies(ctx, LockingStrengthNone, accountID)
	require.NoError(t, err)
	maxSeq := uint32(0)
	for _, p := range existing {
		if p.AccountSeqID > maxSeq {
			maxSeq = p.AccountSeqID
		}
	}

	require.NoError(t, store.ExecuteInTransaction(ctx, func(tx Store) error {
		seq, err := tx.AllocateAccountSeqID(ctx, accountID, types.AccountSeqEntityPolicy)
		if err != nil {
			return err
		}
		require.Equal(t, maxSeq+1, seq, "next id should be max+1 after backfill")

		newPolicy := &types.Policy{
			ID:           "bench-new-policy",
			AccountID:    accountID,
			AccountSeqID: seq,
			Enabled:      true,
			Rules: []*types.PolicyRule{{
				ID:            "bench-new-policy-rule",
				PolicyID:      "bench-new-policy",
				Enabled:       true,
				Action:        types.PolicyTrafficActionAccept,
				Sources:       []string{"groupA"},
				Destinations:  []string{"groupC"},
				Bidirectional: true,
			}},
		}
		return tx.CreatePolicy(ctx, newPolicy)
	}))

	created, err := store.GetPolicyByID(ctx, LockingStrengthNone, accountID, "bench-new-policy")
	require.NoError(t, err)
	require.Equal(t, maxSeq+1, created.AccountSeqID)
}
