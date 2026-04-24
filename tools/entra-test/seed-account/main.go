// seed-account inserts a minimally-viable NetBird Account row + its All
// group into Postgres so the Entra enrolment code path has somewhere to
// create peers. Intended only for the local Entra test harness — it bypasses
// the real AccountManager signup flow, which requires a working IdP.
//
// Usage:
//
//   go run ./tools/entra-test/seed-account \
//     -dsn "host=localhost port=5432 user=netbird password=netbird dbname=netbird sslmode=disable" \
//     -account-id test-account-1 \
//     -groups test-group-1
//
// After this runs, the account referenced by the Entra integration row
// exists and /join/entra/enroll can successfully create peers.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/types"
)

func main() {
	var (
		dsn       = flag.String("dsn", defaultDSN(), "Postgres DSN (libpq key=value or URI)")
		accountID = flag.String("account-id", "test-account-1", "Account ID to create")
		createdBy = flag.String("created-by", "entra-test-harness", "Value for accounts.created_by")
		groups    = flag.String("groups", "test-group-1", "Comma-separated additional group IDs to create (useful as mapping auto_groups targets)")
	)
	flag.Parse()

	db, err := gorm.Open(postgres.Open(*dsn), &gorm.Config{})
	if err != nil {
		die("open postgres: %v", err)
	}

	// Build a proper Account using netbird's type constructors so the
	// JSON-encoded network_net / IPNet field is formatted correctly.
	network := types.NewNetwork()
	acct := &types.Account{
		Id:        *accountID,
		CreatedAt: time.Now().UTC(),
		CreatedBy: *createdBy,
		Domain:    "entra-test.local",
		Network:   network,
		Settings: &types.Settings{
			PeerLoginExpirationEnabled: false,
			PeerLoginExpiration:        types.DefaultPeerLoginExpiration,
			GroupsPropagationEnabled:   true,
			RegularUsersViewBlocked:    false,
			Extra: &types.ExtraSettings{
				UserApprovalRequired: false,
			},
		},
	}

	// Save the accounts row. gorm handles the serializer:json fields.
	if err := db.Save(acct).Error; err != nil {
		die("save account: %v", err)
	}
	fmt.Printf("  [+] account %q seeded (network %s, serial %d)\n", acct.Id, network.Net.String(), network.Serial)

	// Create the All group the enrolment code explicitly adds every peer to.
	allGroup := &types.Group{
		ID:        "all-" + *accountID,
		AccountID: *accountID,
		Name:      "All",
		Issued:    types.GroupIssuedAPI,
	}
	if err := db.Save(allGroup).Error; err != nil {
		die("save All group: %v", err)
	}
	fmt.Printf("  [+] All group %q seeded\n", allGroup.ID)

	// Any extra groups the mappings reference as auto_groups.
	for _, gid := range splitNonEmpty(*groups) {
		g := &types.Group{
			ID:        gid,
			AccountID: *accountID,
			Name:      gid,
			Issued:    types.GroupIssuedAPI,
		}
		if err := db.Save(g).Error; err != nil {
			die("save group %q: %v", gid, err)
		}
		fmt.Printf("  [+] group %q seeded\n", gid)
	}

	fmt.Println("done.")
}

func splitNonEmpty(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func defaultDSN() string {
	if d := os.Getenv("DSN"); d != "" {
		return d
	}
	// Local dev fixture — matches tools/entra-test/docker-compose.yml's
	// default Postgres. Production deployments should pass -dsn or set DSN.
	user := envOrDefault("NB_TEST_PG_USER", "netbird")
	pass := envOrDefault("NB_TEST_PG_PASSWORD", "netbird") // NOSONAR - local dev fixture
	db := envOrDefault("NB_TEST_PG_DB", "netbird")
	return fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s sslmode=disable", user, pass, db)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "seed-account: "+format+"\n", args...)
	os.Exit(1)
}
