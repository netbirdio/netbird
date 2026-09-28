package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
)

// Deprecated: Full
// account operations are no longer supported
func (s *SqlStore) SaveAccount(ctx context.Context, account *types.Account) error {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		if elapsed > 1*time.Second {
			log.WithContext(ctx).Tracef("SaveAccount for account %s exceeded 1s, took: %v", account.Id, elapsed)
		}
	}()

	// todo: remove this check after the issue is resolved
	s.checkAccountDomainBeforeSave(ctx, account.Id, account.Domain)

	generateAccountSQLTypes(account)

	// Encrypt sensitive user data before saving
	for i := range account.UsersG {
		if err := account.UsersG[i].EncryptSensitiveData(s.fieldEncrypt); err != nil {
			return fmt.Errorf("encrypt user: %w", err)
		}
	}

	for _, group := range account.GroupsG {
		group.StoreGroupPeers()
	}

	err := s.transaction(func(tx *gorm.DB) error {
		result := tx.Select(clause.Associations).Delete(account.Policies, "account_id = ?", account.Id)
		if result.Error != nil {
			return result.Error
		}

		result = tx.Select(clause.Associations).Delete(account.UsersG, "account_id = ?", account.Id)
		if result.Error != nil {
			return result.Error
		}

		result = tx.Select(clause.Associations).Delete(account)
		if result.Error != nil {
			return result.Error
		}

		result = tx.
			Session(&gorm.Session{FullSaveAssociations: true}).
			Clauses(clause.OnConflict{UpdateAll: true}).
			Create(account)
		if result.Error != nil {
			return result.Error
		}
		return nil
	})

	took := time.Since(start)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountPersistenceDuration(took)
	}
	log.WithContext(ctx).Debugf("took %d ms to persist an account to the store", took.Milliseconds())

	return err
}

// generateAccountSQLTypes generates the GORM compatible types for the account
func generateAccountSQLTypes(account *types.Account) {
	for _, key := range account.SetupKeys {
		account.SetupKeysG = append(account.SetupKeysG, *key)
	}

	if len(account.SetupKeys) != len(account.SetupKeysG) {
		log.Warnf("SetupKeysG length mismatch for account %s", account.Id)
	}

	for id, peer := range account.Peers {
		peer.ID = id
		account.PeersG = append(account.PeersG, *peer)
	}

	for id, user := range account.Users {
		user.Id = id
		for id, pat := range user.PATs {
			pat.ID = id
			user.PATsG = append(user.PATsG, *pat)
		}
		account.UsersG = append(account.UsersG, *user)
	}

	for id, group := range account.Groups {
		group.ID = id
		group.AccountID = account.Id
		account.GroupsG = append(account.GroupsG, group)
	}

	for id, route := range account.Routes {
		route.ID = id
		account.RoutesG = append(account.RoutesG, *route)
	}

	for id, ns := range account.NameServerGroups {
		ns.ID = id
		account.NameServerGroupsG = append(account.NameServerGroupsG, *ns)
	}
}

// checkAccountDomainBeforeSave temporary method to troubleshoot an issue with domains getting blank
func (s *SqlStore) checkAccountDomainBeforeSave(ctx context.Context, accountID, newDomain string) {
	var acc types.Account
	var domain string
	result := s.db.Model(&acc).Select("domain").Where(idQueryCondition, accountID).Take(&domain)
	if result.Error != nil {
		if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.WithContext(ctx).Errorf("error when getting account %s from the store to check domain: %s", accountID, result.Error)
		}
		return
	}
	if domain != "" && newDomain == "" {
		log.WithContext(ctx).Warnf("saving an account with empty domain when there was a domain set. Previous domain %s, Account ID: %s, Trace: %s", domain, accountID, debug.Stack())
	}
}

func (s *SqlStore) DeleteAccount(ctx context.Context, account *types.Account) error {
	start := time.Now()

	err := s.transaction(func(tx *gorm.DB) error {
		result := tx.Select(clause.Associations).Delete(account.Policies, "account_id = ?", account.Id)
		if result.Error != nil {
			return result.Error
		}

		result = tx.Select(clause.Associations).Delete(account.UsersG, "account_id = ?", account.Id)
		if result.Error != nil {
			return result.Error
		}

		result = tx.Select(clause.Associations).Delete(account.Services, "account_id = ?", account.Id)
		if result.Error != nil {
			return result.Error
		}

		result = tx.Select(clause.Associations).Delete(account)
		if result.Error != nil {
			return result.Error
		}

		return nil
	})

	took := time.Since(start)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountPersistenceDuration(took)
	}
	log.WithContext(ctx).Tracef("took %d ms to delete an account to the store", took.Milliseconds())

	return err
}

func (s *SqlStore) UpdateAccountDomainAttributes(ctx context.Context, accountID string, domain string, category string, isPrimaryDomain bool) error {
	accountCopy := types.Account{
		Domain:                 domain,
		DomainCategory:         category,
		IsDomainPrimaryAccount: isPrimaryDomain,
	}

	fieldsToUpdate := []string{"domain", "domain_category", "is_domain_primary_account"}
	result := s.db.Model(&types.Account{}).
		Select(fieldsToUpdate).
		Where(idQueryCondition, accountID).
		Updates(&accountCopy)
	if result.Error != nil {
		return status.Errorf(status.Internal, "failed to update account domain attributes to store: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "account %s", accountID)
	}

	return nil
}

func (s *SqlStore) GetAccountByPrivateDomain(ctx context.Context, domain string) (*types.Account, error) {
	accountID, err := s.GetAccountIDByPrivateDomain(ctx, LockingStrengthNone, domain)
	if err != nil {
		return nil, err
	}

	// TODO:  rework to not call GetAccount
	return s.GetAccount(ctx, accountID)
}

func (s *SqlStore) GetAccountIDByPrivateDomain(ctx context.Context, lockStrength LockingStrength, domain string) (string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountID string
	result := tx.Model(&types.Account{}).Select("id").
		Where("domain = ? and is_domain_primary_account = ? and domain_category = ?",
			strings.ToLower(domain), true, types.PrivateCategory,
		).Take(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: provided domain is not registered or is not private")
		}
		log.WithContext(ctx).Errorf("error when getting account from the store: %s", result.Error)
		return "", status.NewGetAccountFromStoreError(result.Error)
	}

	return accountID, nil
}

func (s *SqlStore) GetAccountsCounter(ctx context.Context) (int64, error) {
	var count int64
	result := s.db.Model(&types.Account{}).Count(&count)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to get all accounts counter: %w", result.Error)
	}

	return count, nil
}

func (s *SqlStore) GetAllAccounts(ctx context.Context) (all []*types.Account) {
	var accounts []types.Account
	result := s.db.Find(&accounts)
	if result.Error != nil {
		return all
	}

	for _, account := range accounts {
		if acc, err := s.GetAccount(ctx, account.Id); err == nil {
			all = append(all, acc)
		}
	}

	return all
}

func (s *SqlStore) GetAccountMeta(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.AccountMeta, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountMeta types.AccountMeta
	result := tx.Model(&types.Account{}).
		Take(&accountMeta, idQueryCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("error when getting account meta %s from the store: %s", accountID, result.Error)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		return nil, status.NewGetAccountFromStoreError(result.Error)
	}

	return &accountMeta, nil
}

func (s *SqlStore) GetAccount(ctx context.Context, accountID string) (*types.Account, error) {
	if s.pool != nil {
		return s.getAccountPgx(ctx, accountID)
	}
	return s.getAccountGorm(ctx, accountID)
}

func (s *SqlStore) getAccountGorm(ctx context.Context, accountID string) (*types.Account, error) {
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
		Preload("Services.Targets").
		Preload("Domains").
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
		if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt user: %w", err)
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

func (s *SqlStore) getAccountPgx(ctx context.Context, accountID string) (*types.Account, error) {
	account, err := s.getAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 16)

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
		services, err := s.getServices(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.Services = services
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		domains, err := s.ListCustomDomains(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.Domains = domains
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
		if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt user: %w", err)
		}
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

func (s *SqlStore) getAccount(ctx context.Context, accountID string) (*types.Account, error) {
	var account types.Account
	account.Network = &types.Network{}
	const accountQuery = `
		SELECT
			id, created_by, created_at, domain, domain_category, is_domain_primary_account,
			-- Embedded Network
			network_identifier, network_net, network_net_v6, network_dns, network_serial,
			-- Embedded DNSSettings
			dns_settings_disabled_management_groups,
			-- Embedded Settings
			settings_peer_login_expiration_enabled, settings_peer_login_expiration,
			settings_peer_inactivity_expiration_enabled, settings_peer_inactivity_expiration,
			settings_regular_users_view_blocked, settings_groups_propagation_enabled,
			settings_jwt_groups_enabled, settings_jwt_groups_claim_name, settings_jwt_allow_groups,
			settings_routing_peer_dns_resolution_enabled, settings_dns_domain, settings_network_range,
			settings_network_range_v6, settings_ipv6_enabled_groups, settings_lazy_connection_enabled,
			settings_local_mfa_enabled, settings_metrics_push_enabled, settings_agent_network_only,
			settings_dashboard_features, settings_auto_update_version, settings_auto_update_always,
			settings_peer_expose_enabled, settings_peer_expose_groups,
			-- Embedded ExtraSettings
			settings_extra_peer_approval_enabled, settings_extra_user_approval_required,
			settings_extra_integrated_validator, settings_extra_integrated_validator_groups
		FROM accounts WHERE id = $1`

	var (
		sPeerLoginExpirationEnabled      sql.NullBool
		sPeerLoginExpiration             sql.NullInt64
		sPeerInactivityExpirationEnabled sql.NullBool
		sPeerInactivityExpiration        sql.NullInt64
		sRegularUsersViewBlocked         sql.NullBool
		sGroupsPropagationEnabled        sql.NullBool
		sJWTGroupsEnabled                sql.NullBool
		sJWTGroupsClaimName              sql.NullString
		sJWTAllowGroups                  sql.NullString
		sRoutingPeerDNSResolutionEnabled sql.NullBool
		sDNSDomain                       sql.NullString
		sNetworkRange                    sql.NullString
		sNetworkRangeV6                  sql.NullString
		sIPv6EnabledGroups               sql.NullString
		sLazyConnectionEnabled           sql.NullBool
		sLocalMFAEnabled                 sql.NullBool
		sMetricsPushEnabled              sql.NullBool
		sAgentNetworkOnly                sql.NullBool
		sDashboardFeatures               sql.NullString
		autoUpdateVersion                sql.NullString
		autoUpdateAlways                 sql.NullBool
		peerExposeEnabled                sql.NullBool
		peerExposeGroups                 sql.NullString
		sExtraPeerApprovalEnabled        sql.NullBool
		sExtraUserApprovalRequired       sql.NullBool
		sExtraIntegratedValidator        sql.NullString
		sExtraIntegratedValidatorGroups  sql.NullString
		networkNet                       sql.NullString
		networkNetV6                     sql.NullString
		dnsSettingsDisabledGroups        sql.NullString
		networkIdentifier                sql.NullString
		networkDns                       sql.NullString
		networkSerial                    sql.NullInt64
		createdAt                        sql.NullTime
	)
	err := s.pool.QueryRow(ctx, accountQuery, accountID).Scan(
		&account.Id, &account.CreatedBy, &createdAt, &account.Domain, &account.DomainCategory, &account.IsDomainPrimaryAccount,
		&networkIdentifier, &networkNet, &networkNetV6, &networkDns, &networkSerial,
		&dnsSettingsDisabledGroups,
		&sPeerLoginExpirationEnabled, &sPeerLoginExpiration,
		&sPeerInactivityExpirationEnabled, &sPeerInactivityExpiration,
		&sRegularUsersViewBlocked, &sGroupsPropagationEnabled,
		&sJWTGroupsEnabled, &sJWTGroupsClaimName, &sJWTAllowGroups,
		&sRoutingPeerDNSResolutionEnabled, &sDNSDomain, &sNetworkRange,
		&sNetworkRangeV6, &sIPv6EnabledGroups, &sLazyConnectionEnabled,
		&sLocalMFAEnabled, &sMetricsPushEnabled, &sAgentNetworkOnly,
		&sDashboardFeatures, &autoUpdateVersion, &autoUpdateAlways,
		&peerExposeEnabled, &peerExposeGroups,
		&sExtraPeerApprovalEnabled, &sExtraUserApprovalRequired,
		&sExtraIntegratedValidator, &sExtraIntegratedValidatorGroups,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		return nil, status.NewGetAccountFromStoreError(err)
	}

	account.Settings = &types.Settings{Extra: &types.ExtraSettings{}}
	if networkNet.Valid {
		_ = json.Unmarshal([]byte(networkNet.String), &account.Network.Net)
	}
	if createdAt.Valid {
		account.CreatedAt = createdAt.Time
	}
	if dnsSettingsDisabledGroups.Valid {
		_ = json.Unmarshal([]byte(dnsSettingsDisabledGroups.String), &account.DNSSettings.DisabledManagementGroups)
	}
	if networkIdentifier.Valid {
		account.Network.Identifier = networkIdentifier.String
	}
	if networkDns.Valid {
		account.Network.Dns = networkDns.String
	}
	if networkSerial.Valid {
		account.Network.Serial = uint64(networkSerial.Int64)
	}
	if sPeerLoginExpirationEnabled.Valid {
		account.Settings.PeerLoginExpirationEnabled = sPeerLoginExpirationEnabled.Bool
	}
	if sPeerLoginExpiration.Valid {
		account.Settings.PeerLoginExpiration = time.Duration(sPeerLoginExpiration.Int64)
	}
	if sPeerInactivityExpirationEnabled.Valid {
		account.Settings.PeerInactivityExpirationEnabled = sPeerInactivityExpirationEnabled.Bool
	}
	if sPeerInactivityExpiration.Valid {
		account.Settings.PeerInactivityExpiration = time.Duration(sPeerInactivityExpiration.Int64)
	}
	if sRegularUsersViewBlocked.Valid {
		account.Settings.RegularUsersViewBlocked = sRegularUsersViewBlocked.Bool
	}
	if sGroupsPropagationEnabled.Valid {
		account.Settings.GroupsPropagationEnabled = sGroupsPropagationEnabled.Bool
	}
	if sJWTGroupsEnabled.Valid {
		account.Settings.JWTGroupsEnabled = sJWTGroupsEnabled.Bool
	}
	if sJWTGroupsClaimName.Valid {
		account.Settings.JWTGroupsClaimName = sJWTGroupsClaimName.String
	}
	if sRoutingPeerDNSResolutionEnabled.Valid {
		account.Settings.RoutingPeerDNSResolutionEnabled = sRoutingPeerDNSResolutionEnabled.Bool
	}
	if sDNSDomain.Valid {
		account.Settings.DNSDomain = sDNSDomain.String
	}
	if sLazyConnectionEnabled.Valid {
		account.Settings.LazyConnectionEnabled = sLazyConnectionEnabled.Bool
	}
	if sLocalMFAEnabled.Valid {
		account.Settings.LocalMfaEnabled = sLocalMFAEnabled.Bool
	}
	if sMetricsPushEnabled.Valid {
		account.Settings.MetricsPushEnabled = sMetricsPushEnabled.Bool
	}
	if sAgentNetworkOnly.Valid {
		account.Settings.AgentNetworkOnly = sAgentNetworkOnly.Bool
	}
	if sDashboardFeatures.Valid && sDashboardFeatures.String != "" {
		if err := json.Unmarshal([]byte(sDashboardFeatures.String), &account.Settings.DashboardFeatures); err != nil {
			log.WithContext(ctx).Warnf("failed to unmarshal dashboard features for account %s: %v", accountID, err)
		}
	}
	if sJWTAllowGroups.Valid {
		_ = json.Unmarshal([]byte(sJWTAllowGroups.String), &account.Settings.JWTAllowGroups)
	}
	if sNetworkRange.Valid {
		_ = json.Unmarshal([]byte(sNetworkRange.String), &account.Settings.NetworkRange)
	}
	if networkNetV6.Valid {
		_ = json.Unmarshal([]byte(networkNetV6.String), &account.Network.NetV6)
	}
	if sNetworkRangeV6.Valid {
		_ = json.Unmarshal([]byte(sNetworkRangeV6.String), &account.Settings.NetworkRangeV6)
	}
	if sIPv6EnabledGroups.Valid {
		_ = json.Unmarshal([]byte(sIPv6EnabledGroups.String), &account.Settings.IPv6EnabledGroups)
	}
	if autoUpdateAlways.Valid {
		account.Settings.AutoUpdateAlways = autoUpdateAlways.Bool
	}
	if autoUpdateVersion.Valid {
		account.Settings.AutoUpdateVersion = autoUpdateVersion.String
	}
	if peerExposeEnabled.Valid {
		account.Settings.PeerExposeEnabled = peerExposeEnabled.Bool
	}
	if peerExposeGroups.Valid {
		_ = json.Unmarshal([]byte(peerExposeGroups.String), &account.Settings.PeerExposeGroups)
	}

	if sExtraPeerApprovalEnabled.Valid {
		account.Settings.Extra.PeerApprovalEnabled = sExtraPeerApprovalEnabled.Bool
	}
	if sExtraUserApprovalRequired.Valid {
		account.Settings.Extra.UserApprovalRequired = sExtraUserApprovalRequired.Bool
	}
	if sExtraIntegratedValidator.Valid {
		account.Settings.Extra.IntegratedValidator = sExtraIntegratedValidator.String
	}
	if sExtraIntegratedValidatorGroups.Valid {
		_ = json.Unmarshal([]byte(sExtraIntegratedValidatorGroups.String), &account.Settings.Extra.IntegratedValidatorGroups)
	}
	return &account, nil
}

func (s *SqlStore) GetAnyAccountID(ctx context.Context) (string, error) {
	var account types.Account
	result := s.db.Select("id").Order("created_at desc").Limit(1).Find(&account)
	if result.Error != nil {
		return "", status.NewGetAccountFromStoreError(result.Error)
	}
	if result.RowsAffected == 0 {
		return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return account.Id, nil
}

func (s *SqlStore) GetAccountNetwork(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.Network, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountNetwork types.AccountNetwork
	if err := tx.Model(&types.Account{}).Where(idQueryCondition, accountID).Take(&accountNetwork).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		return nil, status.Errorf(status.Internal, "issue getting network from store: %s", err)
	}
	return accountNetwork.Network, nil
}

func (s *SqlStore) GetAccountSettings(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.Settings, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountSettings types.AccountSettings
	if err := tx.Model(&types.Account{}).Where(idQueryCondition, accountID).Take(&accountSettings).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "settings not found")
		}
		return nil, status.Errorf(status.Internal, "issue getting settings from store: %s", err)
	}
	return accountSettings.Settings, nil
}

func (s *SqlStore) GetAccountCreatedBy(ctx context.Context, lockStrength LockingStrength, accountID string) (string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var createdBy string
	result := tx.Model(&types.Account{}).
		Select("created_by").Take(&createdBy, idQueryCondition, accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.NewAccountNotFoundError(accountID)
		}
		return "", status.NewGetAccountFromStoreError(result.Error)
	}

	return createdBy, nil
}

func (s *SqlStore) IncrementNetworkSerial(ctx context.Context, accountId string) error {
	result := s.db.Model(&types.Account{}).Where(idQueryCondition, accountId).Update("network_serial", gorm.Expr("network_serial + 1"))
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to increment network serial count in store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to increment network serial count in store")
	}
	return nil
}

func (s *SqlStore) GetAccountDNSSettings(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.DNSSettings, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountDNSSettings types.AccountDNSSettings
	result := tx.Model(&types.Account{}).
		Take(&accountDNSSettings, idQueryCondition, accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		log.WithContext(ctx).Errorf("failed to get dns settings from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get dns settings from store")
	}
	return &accountDNSSettings.DNSSettings, nil
}

// AccountExists checks whether an account exists by the given ID.
func (s *SqlStore) AccountExists(ctx context.Context, lockStrength LockingStrength, id string) (bool, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountID string
	result := tx.Model(&types.Account{}).
		Select("id").Take(&accountID, idQueryCondition, id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, result.Error
	}

	return accountID != "", nil
}

// GetAccountDomainAndCategory retrieves the Domain and DomainCategory fields for an account based on the given accountID.
func (s *SqlStore) GetAccountDomainAndCategory(ctx context.Context, lockStrength LockingStrength, accountID string) (string, string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var account types.Account
	result := tx.Model(&types.Account{}).Select("domain", "domain_category").
		Where(idQueryCondition, accountID).Take(&account)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", "", status.Errorf(status.NotFound, "account not found")
		}
		return "", "", status.Errorf(status.Internal, "failed to get domain category from store: %v", result.Error)
	}

	return account.Domain, account.DomainCategory, nil
}

// SaveDNSSettings saves the DNS settings to the store.
func (s *SqlStore) SaveDNSSettings(ctx context.Context, accountID string, settings *types.DNSSettings) error {
	result := s.db.Model(&types.Account{}).
		Where(idQueryCondition, accountID).Updates(&types.AccountDNSSettings{DNSSettings: *settings})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save dns settings to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save dns settings to store")
	}

	if result.RowsAffected == 0 {
		return status.NewAccountNotFoundError(accountID)
	}

	return nil
}

// SaveAccountSettings stores the account settings in DB.
func (s *SqlStore) SaveAccountSettings(ctx context.Context, accountID string, settings *types.Settings) error {
	result := s.db.Model(&types.Account{}).
		Select("*").Where(idQueryCondition, accountID).Updates(&types.AccountSettings{Settings: settings})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save account settings to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save account settings to store")
	}

	// MySQL reports RowsAffected=0 for no-op updates where values don't change,
	// unlike SQLite/Postgres which report matched rows. Skip the check since the
	// caller (UpdateAccountSettings) already verified the account exists via
	// GetAccountSettings with LockingStrengthUpdate.

	return nil
}

func (s *SqlStore) CountAccountsByPrivateDomain(ctx context.Context, domain string) (int64, error) {
	var count int64
	result := s.db.Model(&types.Account{}).
		Where("domain = ? AND domain_category = ?",
			strings.ToLower(domain), types.PrivateCategory,
		).Count(&count)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to count accounts by private domain %s: %s", domain, result.Error)
		return 0, status.Errorf(status.Internal, "failed to count accounts by private domain")
	}

	return count, nil
}

func (s *SqlStore) IsPrimaryAccount(ctx context.Context, accountID string) (bool, string, error) {
	var info types.PrimaryAccountInfo
	result := s.db.Model(&types.Account{}).
		Select("is_domain_primary_account, domain").
		Where(idQueryCondition, accountID).
		Take(&info)

	if result.Error != nil {
		return false, "", status.Errorf(status.Internal, "failed to get account info: %v", result.Error)
	}

	return info.IsDomainPrimaryAccount, info.Domain, nil
}

func (s *SqlStore) MarkAccountPrimary(ctx context.Context, accountID string) error {
	result := s.db.Model(&types.Account{}).
		Where(idQueryCondition, accountID).
		Update("is_domain_primary_account", true)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to mark account as primary: %s", result.Error)
		return status.Errorf(status.Internal, "failed to mark account as primary")
	}

	if result.RowsAffected == 0 {
		return status.NewAccountNotFoundError(accountID)
	}

	return nil
}

type accountNetworkPatch struct {
	Network *types.Network `gorm:"embedded;embeddedPrefix:network_"`
}

func (s *SqlStore) UpdateAccountNetwork(ctx context.Context, accountID string, ipNet net.IPNet) error {
	patch := accountNetworkPatch{
		Network: &types.Network{Net: ipNet},
	}

	result := s.db.
		Model(&types.Account{}).
		Where(idQueryCondition, accountID).
		Updates(&patch)

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update account network: %v", result.Error)
		return status.Errorf(status.Internal, "failed to update account network")
	}
	if result.RowsAffected == 0 {
		return status.NewAccountNotFoundError(accountID)
	}
	return nil
}

// UpdateAccountNetworkV6 updates the IPv6 network range for the account.
func (s *SqlStore) UpdateAccountNetworkV6(ctx context.Context, accountID string, ipNet net.IPNet) error {
	patch := accountNetworkPatch{
		Network: &types.Network{NetV6: ipNet},
	}

	result := s.db.
		Model(&types.Account{}).
		Where(idQueryCondition, accountID).
		Updates(&patch)

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update account network v6: %v", result.Error)
		return status.Errorf(status.Internal, "update account network v6")
	}
	if result.RowsAffected == 0 {
		return status.NewAccountNotFoundError(accountID)
	}
	return nil
}
