package networkmap_pgsql

import (
	"context"
	"testing"
	"time"

	_ "embed"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetGroups(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	_, err = s.Pool.Exec(ctx, "insert into groups (id, account_id, name, resources, public_id) VALUES('test-group-id-1','ck7bnf2t2r9s739pkug0','test-group-1', '[{\"ID\":\"cui7q2jl0ubs73d8qpi0\",\"Type\":\"host\"}]','public-id-1')")
	assert.NoError(t, err)

	groups, _, err := s.GetGroups(ctx, "ck7bnf2t2r9s739pkug0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)
	assert.Contains(t,
		groups,
		nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	)
	assert.Contains(t,
		groups,
		nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	)
}

func TestGetPeers(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	peers, clusterToPeerIdx, err := s.GetPeers(ctx, "d8pqjvbl0ubs73e8cjkg") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)
	assert.NotEmpty(t, clusterToPeerIdx)

	t.Log(peers)
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
}

func TestGetPolicies(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	peers, idx1, idx2, err := s.GetPolicies(ctx, "ck7bnf2t2r9s739pkug0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)
	assert.NotEmpty(t, idx1)
	assert.NotEmpty(t, idx2)

	t.Log(peers)
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
}

func TestGetRoutes(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	peers, err := s.GetRoutes(ctx, "csg5iabl0ubs7398nf1g") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)

	t.Log(peers)
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
}

func TestGetNSGroups(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	groups, err := s.GetNameServerGroups(ctx, "cl3h77qfic3c738mkja0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)

	t.Log(groups)
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
}

func TestGetNetworkResources(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	res, err := s.GetNetworkResources(ctx, "cag86v2t2r9s73d0416g") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)

	t.Log(res)
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
}

func TestGetNetworkRouters(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	c, _ := s.Pool.Acquire(ctx)
	res, err := GetNetworkRoutersViaPgxConnection(ctx, c.Conn(), "d29f99jl0ubs73cm8ce0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)

	t.Log(res)
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
}

func TestGetNetwork(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	n, err := s.GetNetwork(ctx, "d29f99jl0ubs73cm8ce0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)

	t.Log(n)
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
}

func TestGetAccountZones(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	zones, err := s.GetAppliedZoneCandidates(ctx, "d4g66rjl0ubs73b2q3b0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)

	t.Log(zones)
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
}

func TestGetAccountSetings(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	settings, err := s.GetAccountSettings(ctx, "d5n27dafadhs73bt5ovg") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)
	assert.Equal(t, nmdata.AccountSettingsInfo{
		PeerLoginExpirationEnabled:      true,
		PeerLoginExpiration:             86400000000000 * time.Nanosecond,
		PeerInactivityExpirationEnabled: true,
		PeerInactivityExpiration:        600000000000 * time.Nanosecond,
	}, settings)
}

func TestGetPostureChecks(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	checks, idx, err := s.GetPostureChecks(ctx, "cdfcks2t2r9s73a58us0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)
	assert.NotEmpty(t, idx)

	t.Log(checks)
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
}

func TestGetAllowedUserIds(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	userIds, groupToUserIds, err := s.GetAllowedUsers(ctx, "cus73sbl0ubs73cfoo90") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)
	assert.NotEmpty(t, userIds)
	assert.NotEmpty(t, groupToUserIds)
}

func TestGetDnsSettings(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	set, err := s.GetDnsSettings(ctx, "ckvdmrqfic3c739ihh5g") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)
	assert.NotEmpty(t, set.DisabledManagementGroups)
}

func TestGetDomains(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	domains, err := s.GetDomains(ctx, "d8f79r2fadhs73c6uc0g") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)
	assert.NotEmpty(t, domains)
}

func TestGetServices(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	svcs, err := s.GetPrivateServices(ctx, "d7jlh32fadhs73btp9u0") //"d6snsejl0ubs738s3f40") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)
	assert.NotEmpty(t, svcs)
}
