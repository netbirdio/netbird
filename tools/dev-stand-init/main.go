// Package main provides a CLI tool to bootstrap a developer/CI management stand.
//
// It directly seeds the management SQLite database with:
//   - A dev admin account (single-account mode domain: dev.netbird.localhost)
//   - An admin service user with a known Personal Access Token (PAT)
//   - A reusable setup key for connecting test peers
//
// This avoids browser-based OAuth flows when setting up automated E2E tests.
// Intended for local development and CI only, never for production.
//
// Usage:
//
//	dev-stand-init --db /var/lib/netbird --token nbp_XXXX
//
// The tool is idempotent: running it on a database that already has accounts is
// a no-op (prints the existing token env-var hint and exits 0).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/base62"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/route"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

const (
	devDomain          = "dev.netbird.localhost"
	devInitPATID       = "dev-init-pat-0000000001"
	devInitPATName     = "Dev Admin Token (automated)"
	devInitSvcUserName = "Dev Admin"
	devSetupKeyName    = "e2e-test-key"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dbPath := flag.String("db", "/var/lib/netbird", "Path to management data directory (contains store.db)")
	token := flag.String("token", os.Getenv("NETBIRD_DEV_INIT_TOKEN"), "PAT token to create (or NETBIRD_DEV_INIT_TOKEN env var)")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	if *verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	if *token == "" {
		return fmt.Errorf("--token or NETBIRD_DEV_INIT_TOKEN is required")
	}
	if err := validateToken(*token); err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	ctx := context.Background()

	st, err := store.NewSqliteStore(ctx, *dbPath, nil, false)
	if err != nil {
		return fmt.Errorf("failed to open database %s: %w", *dbPath, err)
	}
	defer func() { _ = st.Close(ctx) }()

	count, err := st.GetAccountsCounter(ctx)
	if err != nil {
		return fmt.Errorf("failed to count accounts: %w", err)
	}
	if count > 0 {
		log.Infof("Database already has %d account(s), nothing to do", count)
		fmt.Fprintf(os.Stdout, "NETBIRD_TEST_TOKEN=%s\n", *token)
		return nil
	}

	// Build a minimal account
	accountID := xid.New().String()
	serviceUserID := xid.New().String()

	account := buildDevAccount(ctx, accountID, serviceUserID)
	//nolint:staticcheck // SaveAccount is deprecated for production use; acceptable in dev bootstrap tool.
	if err := st.SaveAccount(ctx, account); err != nil {
		return fmt.Errorf("failed to save account: %w", err)
	}
	log.Infof("Created dev account (id=%s)", accountID)

	// Create PAT for the service user
	hash := sha256.Sum256([]byte(*token))
	encodedHash := base64.StdEncoding.EncodeToString(hash[:])
	expiry := time.Now().Add(365 * 24 * time.Hour)
	pat := &types.PersonalAccessToken{
		ID:             devInitPATID,
		UserID:         serviceUserID,
		Name:           devInitPATName,
		HashedToken:    encodedHash,
		ExpirationDate: &expiry,
		CreatedBy:      serviceUserID,
		CreatedAt:      time.Now().UTC(),
	}
	if err := st.SavePAT(ctx, pat); err != nil {
		return fmt.Errorf("failed to save PAT: %w", err)
	}
	log.Infof("Created admin PAT (id=%s)", devInitPATID)

	// Create a reusable setup key so test peers can connect.
	// GenerateSetupKey returns (SetupKey with Key=sha256(plainKey), plainKey).
	// We store the SetupKey (hashed) and export the plaintext for client use —
	// the management server re-hashes the plaintext before the DB lookup.
	setupKey, plainKey := types.GenerateSetupKey(devSetupKeyName, types.SetupKeyReusable, 24*time.Hour, []string{}, 0, false, false)
	setupKey.AccountID = accountID
	if err := st.SaveSetupKey(ctx, setupKey); err != nil {
		log.Warnf("Failed to save setup key: %v", err)
	} else {
		log.Infof("Created setup key (id=%s)", setupKey.Id)
		fmt.Fprintf(os.Stdout, "NETBIRD_SETUP_KEY=%s\n", plainKey)
	}

	fmt.Fprintf(os.Stdout, "NETBIRD_TEST_TOKEN=%s\n", *token)
	fmt.Fprintf(os.Stdout, "NETBIRD_ACCOUNT_ID=%s\n", accountID)
	log.Info("Dev stand initialized successfully")
	return nil
}

// buildDevAccount constructs a minimal account with a single admin service user.
func buildDevAccount(ctx context.Context, accountID, serviceUserID string) *types.Account {
	_ = ctx

	network := types.NewNetwork()
	svcUser := types.NewUser(serviceUserID, types.UserRoleAdmin, true, true, devInitSvcUserName, []string{}, types.UserIssuedAPI, "", "")
	svcUser.AccountID = accountID

	acc := &types.Account{
		Id:        accountID,
		CreatedAt: time.Now().UTC(),
		CreatedBy: serviceUserID,
		Domain:    devDomain,
		Network:   network,
		Peers:     map[string]*nbpeer.Peer{},
		Users: map[string]*types.User{
			serviceUserID: svcUser,
		},
		SetupKeys:         map[string]*types.SetupKey{},
		Routes:            map[route.ID]*route.Route{},
		NameServerGroups:  map[string]*nbdns.NameServerGroup{},
		DNSSettings:       types.DNSSettings{DisabledManagementGroups: []string{}},
		Settings: &types.Settings{
			PeerLoginExpirationEnabled:      true,
			PeerLoginExpiration:             types.DefaultPeerLoginExpiration,
			GroupsPropagationEnabled:        true,
			RegularUsersViewBlocked:         true,
			PeerInactivityExpirationEnabled: false,
			PeerInactivityExpiration:        types.DefaultPeerInactivityExpiration,
			RoutingPeerDNSResolutionEnabled: true,
		},
	}
	if err := acc.AddAllGroup(false); err != nil {
		log.Warnf("Failed to add all group: %v", err)
	}
	return acc
}

// validateToken checks that the PAT has valid format and checksum.
func validateToken(token string) error {
	if len(token) != types.PATLength {
		return fmt.Errorf("expected %d chars, got %d", types.PATLength, len(token))
	}
	if token[:len(types.PATPrefix)] != types.PATPrefix {
		return fmt.Errorf("must start with %s", types.PATPrefix)
	}
	secret := token[len(types.PATPrefix) : len(types.PATPrefix)+types.PATSecretLength]
	checksumStr := token[len(types.PATPrefix)+types.PATSecretLength:]

	checksum, err := base62.Decode(checksumStr)
	if err != nil {
		return fmt.Errorf("checksum decode: %w", err)
	}
	if crc32.ChecksumIEEE([]byte(secret)) != checksum {
		return fmt.Errorf("checksum mismatch")
	}
	return nil
}
