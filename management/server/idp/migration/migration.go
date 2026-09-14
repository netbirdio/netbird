// Package migration provides utility functions for migrating from the external IdP solution in pre v0.62.0
// to the new embedded IdP manager (Dex based), which is the default in v0.62.0 and later.
// It includes functions to seed connectors and migrate existing users to use these connectors.
package migration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/types"
)

// Server is the dependency interface that migration functions use to access
// the main data store and the activity event store.
type Server interface {
	Store() Store
	EventStore() EventStore // may return nil
}

const (
	idpSeedInfoKey = "IDP_SEED_INFO"
	dryRunEnvKey   = "NB_IDP_MIGRATION_DRY_RUN"
)

func isDryRun() bool {
	return os.Getenv(dryRunEnvKey) == "true"
}

var ErrNoSeedInfo = errors.New("no seed info found in environment")

// SeedConnectorFromEnv reads the IDP_SEED_INFO env var, base64-decodes it,
// and JSON-unmarshals it into a dex.Connector. Returns nil if not set.
func SeedConnectorFromEnv() (*dex.Connector, error) {
	val, ok := os.LookupEnv(idpSeedInfoKey)
	if !ok || val == "" {
		return nil, ErrNoSeedInfo
	}

	decoded, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var conn dex.Connector
	if err := json.Unmarshal(decoded, &conn); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	return &conn, nil
}

// MigrateUsersToStaticConnectors re-keys every user ID in the main store (and
// the activity store, if present) so that it encodes the given connector ID,
// skipping users that have already been migrated. Set NB_IDP_MIGRATION_DRY_RUN=true
// to log what would happen without writing any changes.
func MigrateUsersToStaticConnectors(s Server, conn *dex.Connector) error {
	ctx := context.Background()

	if isDryRun() {
		log.Info("[DRY RUN] migration dry-run mode enabled, no changes will be written")
	}

	users, err := s.Store().ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	// Reconciliation pass: fix activity store for users already migrated in main DB
	// but whose activity references may still use old IDs (from a previous partial failure).
	if s.EventStore() != nil && !isDryRun() {
		if err := reconcileActivityStore(ctx, s.EventStore(), users); err != nil {
			return err
		}
	}

	var migratedCount, skippedCount int

	for _, user := range users {
		_, _, decErr := dex.DecodeDexUserID(user.Id)
		if decErr == nil {
			skippedCount++
			continue
		}

		newUserID := dex.EncodeDexUserID(user.Id, conn.ID)

		if isDryRun() {
			log.Infof("[DRY RUN] would migrate user %s -> %s (account: %s)", user.Id, newUserID, user.AccountID)
			migratedCount++
			continue
		}

		if err := migrateUser(ctx, s, user.Id, user.AccountID, newUserID); err != nil {
			return err
		}

		migratedCount++
	}

	if isDryRun() {
		log.Infof("[DRY RUN] migration summary: %d users would be migrated, %d already migrated", migratedCount, skippedCount)
	} else {
		log.Infof("migration complete: %d users migrated, %d already migrated", migratedCount, skippedCount)
	}

	return nil
}

// reconcileActivityStore updates activity store references for users already migrated
// in the main DB whose activity entries may still use old IDs from a previous partial failure.
func reconcileActivityStore(ctx context.Context, eventStore EventStore, users []*types.User) error {
	for _, user := range users {
		originalID, _, err := dex.DecodeDexUserID(user.Id)
		if err != nil {
			// skip users that aren't migrated, they will be handled in the main migration loop
			continue
		}
		if err := eventStore.UpdateUserID(ctx, originalID, user.Id); err != nil {
			return fmt.Errorf("reconcile activity store for user %s: %w", user.Id, err)
		}
	}
	return nil
}

// migrateUser updates a single user's ID in both the main store and the activity store.
func migrateUser(ctx context.Context, s Server, oldID, accountID, newID string) error {
	if err := s.Store().UpdateUserID(ctx, accountID, oldID, newID); err != nil {
		return fmt.Errorf("failed to update user ID for user %s: %w", oldID, err)
	}

	if s.EventStore() == nil {
		return nil
	}

	if err := s.EventStore().UpdateUserID(ctx, oldID, newID); err != nil {
		return fmt.Errorf("failed to update activity store user ID for user %s: %w", oldID, err)
	}

	return nil
}

// PopulateUserInfo fetches user email and name from the external IDP and updates
// the store for users that are missing this information.
func PopulateUserInfo(s Server, idpManager idp.Manager, dryRun bool) error {
	ctx := context.Background()

	users, err := s.Store().ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	// Build a map of IDP user ID -> UserData from the external IDP
	allAccounts, err := idpManager.GetAllAccounts(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch accounts from IDP: %w", err)
	}

	idpUsers := make(map[string]*idp.UserData)
	for _, accountUsers := range allAccounts {
		for _, userData := range accountUsers {
			idpUsers[userData.ID] = userData
		}
	}

	log.Infof("fetched %d users from IDP", len(idpUsers))

	var updatedCount, skippedCount, notFoundCount int

	for _, user := range users {
		if user.IsServiceUser {
			skippedCount++
			continue
		}

		if user.Email != "" && user.Name != "" {
			skippedCount++
			continue
		}

		// The user ID in the store may be the original IDP ID or a Dex-encoded ID.
		// Try to decode the Dex format first to get the original IDP ID.
		lookupID := user.Id
		if originalID, _, decErr := dex.DecodeDexUserID(user.Id); decErr == nil {
			lookupID = originalID
		}

		idpUser, found := idpUsers[lookupID]
		if !found {
			notFoundCount++
			log.Debugf("user %s (lookup: %s) not found in IDP, skipping", user.Id, lookupID)
			continue
		}

		email := user.Email
		name := user.Name
		if email == "" && idpUser.Email != "" {
			email = idpUser.Email
		}
		if name == "" && idpUser.Name != "" {
			name = idpUser.Name
		}

		if email == user.Email && name == user.Name {
			skippedCount++
			continue
		}

		if dryRun {
			log.Infof("[DRY RUN] would update user %s: email=%q, name=%q", user.Id, email, name)
			updatedCount++
			continue
		}

		if err := s.Store().UpdateUserInfo(ctx, user.Id, email, name); err != nil {
			return fmt.Errorf("failed to update user info for %s: %w", user.Id, err)
		}

		log.Infof("updated user %s: email=%q, name=%q", user.Id, email, name)
		updatedCount++
	}

	if dryRun {
		log.Infof("[DRY RUN] user info summary: %d would be updated, %d skipped, %d not found in IDP", updatedCount, skippedCount, notFoundCount)
	} else {
		log.Infof("user info population complete: %d updated, %d skipped, %d not found in IDP", updatedCount, skippedCount, notFoundCount)
	}

	return nil
}

const DefaultSingleAccountDomain = "netbird.selfhosted"

var (
	ErrMultipleAccounts = errors.New("the embedded IdP supports a single account only")
	ErrUnusableDomain   = errors.New("domain cannot be resolved in single account mode")
	ErrDomainConflict   = errors.New("requested domain conflicts with the account domain")
)

var resolvableDomainRegexp = regexp.MustCompile(`^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$`)

// RequireSingleAccount refuses to migrate an instance that holds more than one account.
func RequireSingleAccount(s Server) error {
	accountsCounter, err := s.Store().GetAccountsCounter(context.Background())
	if err != nil {
		return fmt.Errorf("failed to count accounts: %w", err)
	}

	if accountsCounter > 1 {
		return errMultipleAccounts(accountsCounter)
	}

	return nil
}

func errMultipleAccounts(accountsCounter int64) error {
	return fmt.Errorf("%w: this instance has %d accounts. Identity provider connectors are stored without "+
		"an account scope, so every account would share and be able to manage the same connectors. "+
		"Consolidate this instance to a single account, or keep using an external IdP, before migrating",
		ErrMultipleAccounts, accountsCounter)
}

func NormalizeSingleAccountDomain(singleAccountDomain string) (string, error) {
	if singleAccountDomain == "" {
		singleAccountDomain = DefaultSingleAccountDomain
	}

	singleAccountDomain = strings.ToLower(singleAccountDomain)
	if !resolvableDomainRegexp.MatchString(singleAccountDomain) {
		return "", fmt.Errorf("%w: %q must contain at least one dot and only lowercase letters, digits and "+
			"hyphens, otherwise users cannot join the existing account", ErrUnusableDomain, singleAccountDomain)
	}

	return singleAccountDomain, nil
}

// resolveAccountDomain picks the domain the account should end up with. The account keeps a usable
// domain of its own, the configured one only fills a blank. Anything else is a conflict to report.
func resolveAccountDomain(accountID, accountDomain, singleAccountDomain string, requested bool) (string, error) {
	accountDomain = strings.ToLower(accountDomain)

	if accountDomain == "" {
		return singleAccountDomain, nil
	}

	if !resolvableDomainRegexp.MatchString(accountDomain) {
		return "", fmt.Errorf("%w: account %s has domain %q, which must contain at least one dot and only "+
			"lowercase letters, digits and hyphens. Correct the account domain before migrating",
			ErrUnusableDomain, accountID, accountDomain)
	}

	if requested && accountDomain != singleAccountDomain {
		return "", fmt.Errorf("%w: account %s already uses domain %q but %q was requested. Re-run without "+
			"--single-account-mode-domain to keep %q, or correct the account domain first",
			ErrDomainConflict, accountID, accountDomain, singleAccountDomain, accountDomain)
	}

	return accountDomain, nil
}

// EnsureSingleAccountDomain gives the remaining account the domain attributes single account mode
// resolves against, so users can still join it after the migration.
func EnsureSingleAccountDomain(s Server, singleAccountDomain string) error {
	plan, err := planSingleAccountDomain(s, singleAccountDomain)
	if err != nil {
		return err
	}
	if plan.skip {
		return nil
	}

	if isDryRun() {
		log.Infof("[DRY RUN] would set account %s domain to %q, category to %q and mark it as the primary domain account "+
			"(currently domain=%q primary=%v)", plan.accountID, plan.domain, types.PrivateCategory,
			plan.currentDomain, plan.isPrimary)
		return nil
	}

	if err := s.Store().UpdateAccountDomainAttributes(context.Background(), plan.accountID, plan.domain,
		types.PrivateCategory, true); err != nil {
		return fmt.Errorf("failed to update domain attributes of account %s: %w", plan.accountID, err)
	}

	log.Infof("account %s now resolves in single account mode with domain %q", plan.accountID, plan.domain)
	return nil
}

// CheckSingleAccountDomain reports whether EnsureSingleAccountDomain would succeed, without writing.
func CheckSingleAccountDomain(s Server, singleAccountDomain string) error {
	_, err := planSingleAccountDomain(s, singleAccountDomain)
	return err
}

type singleAccountDomainPlan struct {
	accountID     string
	domain        string
	currentDomain string
	isPrimary     bool
	skip          bool
}

// planSingleAccountDomain decides what the account's domain attributes should become. It reads
// only, so it can run both as a preflight and as the first half of the update.
func planSingleAccountDomain(s Server, singleAccountDomain string) (singleAccountDomainPlan, error) {
	ctx := context.Background()

	// An empty value means the operator did not pick a domain, so the default is only a fallback.
	requested := singleAccountDomain != ""

	singleAccountDomain, err := NormalizeSingleAccountDomain(singleAccountDomain)
	if err != nil {
		return singleAccountDomainPlan{}, err
	}

	accountsCounter, err := s.Store().GetAccountsCounter(ctx)
	if err != nil {
		return singleAccountDomainPlan{}, fmt.Errorf("failed to count accounts: %w", err)
	}
	// The count is checked again here: it is read long after RequireSingleAccount, and marking an
	// arbitrary account as the primary one for the domain would be wrong.
	switch {
	case accountsCounter == 0:
		log.Info("no accounts yet, nothing to prepare for single account mode")
		return singleAccountDomainPlan{skip: true}, nil
	case accountsCounter > 1:
		return singleAccountDomainPlan{}, errMultipleAccounts(accountsCounter)
	}

	accountID, err := s.Store().GetAnyAccountID(ctx)
	if err != nil {
		return singleAccountDomainPlan{}, fmt.Errorf("failed to get the existing account: %w", err)
	}

	isPrimary, accountDomain, err := s.Store().IsPrimaryAccount(ctx, accountID)
	if err != nil {
		return singleAccountDomainPlan{}, fmt.Errorf("failed to read domain attributes of account %s: %w", accountID, err)
	}

	domain, err := resolveAccountDomain(accountID, accountDomain, singleAccountDomain, requested)
	if err != nil {
		return singleAccountDomainPlan{}, err
	}

	return singleAccountDomainPlan{
		accountID:     accountID,
		domain:        domain,
		currentDomain: accountDomain,
		isPrimary:     isPrimary,
	}, nil
}
