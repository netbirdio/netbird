package networkmap_pgsql

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "embed"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

//go:embed test_db.sql
var initDb string

func TestGetGroups(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	_, err = s.Pool.Query(ctx, "insert into groups (id, account_id, name, resources, public_id) VALUES('test-group-id-1','ck7bnf2t2r9s739pkug0','test-group-1', '[{\"ID\":\"cui7q2jl0ubs73d8qpi0\",\"Type\":\"host\"}]','public-id-1')")
	assert.NoError(t, err)

	groups, err := s.GetGroups(ctx, "ck7bnf2t2r9s739pkug0") //"ckd7ee2fic3c73dtendg")
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

	peers, err := s.GetPeers(ctx, "ck7bnf2t2r9s739pkug0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)

	fmt.Print(peers)
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
}

func TestGetPolocies(t *testing.T) {
	ctx := context.TODO()

	s, err := NewPostgresqlStore(ctx, "postgresql://root:netbird@localhost:5432/netbird")
	assert.NoError(t, err)
	//	err = loadSQL(ctx, s.pool, initDb)
	//assert.NoError(t, err)

	peers, err := s.GetPolicies(ctx, "ck7bnf2t2r9s739pkug0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)

	fmt.Print(peers)
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

	fmt.Print(peers)
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

	fmt.Print(groups)
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

	fmt.Print(res)
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

	res, err := s.GetNetworkRouters(ctx, "d29f99jl0ubs73cm8ce0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)

	fmt.Print(res)
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

	fmt.Print(n)
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

	zones, err := s.GetAccountZones(ctx, "d4g66rjl0ubs73b2q3b0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)

	fmt.Print(zones)
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

	checks, err := s.GetPostureChecks(ctx, "cdfcks2t2r9s73a58us0") //"ckd7ee2fic3c73dtendg")
	assert.NoError(t, err)

	fmt.Print(checks)
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
	// assert.Contains(t,
	// 	groups,
	// 	nmdata.Group{Name: "All", PublicID: "d9aejspvcsu517nkh4a0", Resources: []nmdata.Resource{{ID: "cui7olrl0ubs73d8qpe0", Type: "subnet"}, {ID: "cui7q2jl0ubs73d8qpi0", Type: "host"}}},
	// )
}

func loadSQL(ctx context.Context, pool *pgxpool.Pool, initdb string) error {
	queries := strings.Split(string(initdb), ";")

	for _, query := range queries {
		query = strings.TrimSpace(query)
		if query != "" {
			_, err := pool.Query(ctx, query)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
