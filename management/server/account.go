package server

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/eko/gocache/v3/cache"
	cacheStore "github.com/eko/gocache/v3/store"
	gocache "github.com/patrickmn/go-cache"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/base62"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/integrated_validator"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"
)

const (
	CacheExpirationMax         = 7 * 24 * 3600 * time.Second // 7 days
	CacheExpirationMin         = 3 * 24 * 3600 * time.Second // 3 days
	peerSchedulerRetryInterval = 3 * time.Second
	emptyUserID                = "empty user ID in claims"
	errorGettingDomainAccIDFmt = "error getting account ID by private domain: %v"
)

type userLoggedInOnce bool

type ExternalCacheManager cache.CacheInterface[*idp.UserData]

func cacheEntryExpiration() time.Duration {
	r := rand.Intn(int(CacheExpirationMax.Milliseconds()-CacheExpirationMin.Milliseconds())) + int(CacheExpirationMin.Milliseconds())
	return time.Duration(r) * time.Millisecond
}

type AccountManager interface {
	GetOrCreateAccountByUser(ctx context.Context, userId, domain string) (*types.Account, error)
	GetAccount(ctx context.Context, accountID string) (*types.Account, error)
	CreateSetupKey(ctx context.Context, accountID string, keyName string, keyType types.SetupKeyType, expiresIn time.Duration,
		autoGroups []string, usageLimit int, userID string, ephemeral bool) (*types.SetupKey, error)
	SaveSetupKey(ctx context.Context, accountID string, key *types.SetupKey, userID string) (*types.SetupKey, error)
	CreateUser(ctx context.Context, accountID, initiatorUserID string, key *types.UserInfo) (*types.UserInfo, error)
	DeleteUser(ctx context.Context, accountID, initiatorUserID string, targetUserID string) error
	DeleteRegularUsers(ctx context.Context, accountID, initiatorUserID string, targetUserIDs []string) error
	InviteUser(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) error
	ListSetupKeys(ctx context.Context, accountID, userID string) ([]*types.SetupKey, error)
	SaveUser(ctx context.Context, accountID, initiatorUserID string, update *types.User) (*types.UserInfo, error)
	SaveOrAddUser(ctx context.Context, accountID, initiatorUserID string, update *types.User, addIfNotExists bool) (*types.UserInfo, error)
	SaveOrAddUsers(ctx context.Context, accountID, initiatorUserID string, updates []*types.User, addIfNotExists bool) ([]*types.UserInfo, error)
	GetSetupKey(ctx context.Context, accountID, userID, keyID string) (*types.SetupKey, error)
	GetAccountByID(ctx context.Context, accountID string, userID string) (*types.Account, error)
	AccountExists(ctx context.Context, accountID string) (bool, error)
	GetAccountIDByUserID(ctx context.Context, userID, domain string) (string, error)
	GetAccountIDFromToken(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error)
	CheckUserAccessByJWTGroups(ctx context.Context, claims jwtclaims.AuthorizationClaims) error
	GetAccountFromPAT(ctx context.Context, pat string) (*types.Account, *types.User, *types.PersonalAccessToken, error)
	DeleteAccount(ctx context.Context, accountID, userID string) error
	MarkPATUsed(ctx context.Context, tokenID string) error
	GetUserByID(ctx context.Context, id string) (*types.User, error)
	GetUser(ctx context.Context, claims jwtclaims.AuthorizationClaims) (*types.User, error)
	ListUsers(ctx context.Context, accountID string) ([]*types.User, error)
	GetPeers(ctx context.Context, accountID, userID string) ([]*nbpeer.Peer, error)
	MarkPeerConnected(ctx context.Context, peerKey string, connected bool, realIP net.IP, accountID string) error
	DeletePeer(ctx context.Context, accountID, peerID, userID string) error
	UpdatePeer(ctx context.Context, accountID, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, error)
	GetNetworkMap(ctx context.Context, peerID string) (*types.NetworkMap, error)
	GetPeerNetwork(ctx context.Context, peerID string) (*types.Network, error)
	AddPeer(ctx context.Context, setupKey, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error)
	CreatePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenName string, expiresIn int) (*types.PersonalAccessTokenGenerated, error)
	DeletePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) error
	GetPAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) (*types.PersonalAccessToken, error)
	GetAllPATs(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) ([]*types.PersonalAccessToken, error)
	GetUsersFromAccount(ctx context.Context, accountID, userID string) ([]*types.UserInfo, error)
	GetGroup(ctx context.Context, accountId, groupID, userID string) (*types.Group, error)
	GetAllGroups(ctx context.Context, accountID, userID string) ([]*types.Group, error)
	GetGroupByName(ctx context.Context, groupName, accountID string) (*types.Group, error)
	SaveGroup(ctx context.Context, accountID, userID string, group *types.Group) error
	SaveGroups(ctx context.Context, accountID, userID string, newGroups []*types.Group) error
	DeleteGroup(ctx context.Context, accountId, userId, groupID string) error
	DeleteGroups(ctx context.Context, accountId, userId string, groupIDs []string) error
	GroupAddPeer(ctx context.Context, accountId, groupID, peerID string) error
	GroupDeletePeer(ctx context.Context, accountId, groupID, peerID string) error
	GetPeerGroups(ctx context.Context, accountID, peerID string) ([]*types.Group, error)
	GetPolicy(ctx context.Context, accountID, policyID, userID string) (*types.Policy, error)
	SavePolicy(ctx context.Context, accountID, userID string, policy *types.Policy) (*types.Policy, error)
	DeletePolicy(ctx context.Context, accountID, policyID, userID string) error
	ListPolicies(ctx context.Context, accountID, userID string) ([]*types.Policy, error)
	GetRoute(ctx context.Context, accountID string, routeID route.ID, userID string) (*route.Route, error)
	CreateRoute(ctx context.Context, accountID string, prefix netip.Prefix, networkType route.NetworkType, domains domain.List, peerID string, peerGroupIDs []string, description string, netID route.NetID, masquerade bool, metric int, groups, accessControlGroupIDs []string, enabled bool, userID string, keepRoute bool) (*route.Route, error)
	SaveRoute(ctx context.Context, accountID, userID string, route *route.Route) error
	DeleteRoute(ctx context.Context, accountID string, routeID route.ID, userID string) error
	ListRoutes(ctx context.Context, accountID, userID string) ([]*route.Route, error)
	GetNameServerGroup(ctx context.Context, accountID, userID, nsGroupID string) (*nbdns.NameServerGroup, error)
	CreateNameServerGroup(ctx context.Context, accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string, searchDomainsEnabled bool) (*nbdns.NameServerGroup, error)
	SaveNameServerGroup(ctx context.Context, accountID, userID string, nsGroupToSave *nbdns.NameServerGroup) error
	DeleteNameServerGroup(ctx context.Context, accountID, nsGroupID, userID string) error
	ListNameServerGroups(ctx context.Context, accountID string, userID string) ([]*nbdns.NameServerGroup, error)
	GetDNSDomain() string
	StoreEvent(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any)
	GetEvents(ctx context.Context, accountID, userID string) ([]*activity.Event, error)
	GetDNSSettings(ctx context.Context, accountID string, userID string) (*types.DNSSettings, error)
	SaveDNSSettings(ctx context.Context, accountID string, userID string, dnsSettingsToSave *types.DNSSettings) error
	GetPeer(ctx context.Context, accountID, peerID, userID string) (*nbpeer.Peer, error)
	UpdateAccountSettings(ctx context.Context, accountID, userID string, newSettings *types.Settings) (*types.Account, error)
	LoginPeer(ctx context.Context, login PeerLogin) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error)                // used by peer gRPC API
	SyncPeer(ctx context.Context, sync PeerSync, accountID string) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error) // used by peer gRPC API
	GetAllConnectedPeers() (map[string]struct{}, error)
	HasConnectedChannel(peerID string) bool
	GetExternalCacheManager() ExternalCacheManager
	GetPostureChecks(ctx context.Context, accountID, postureChecksID, userID string) (*posture.Checks, error)
	SavePostureChecks(ctx context.Context, accountID, userID string, postureChecks *posture.Checks) (*posture.Checks, error)
	DeletePostureChecks(ctx context.Context, accountID, postureChecksID, userID string) error
	ListPostureChecks(ctx context.Context, accountID, userID string) ([]*posture.Checks, error)
	GetIdpManager() idp.Manager
	UpdateIntegratedValidatorGroups(ctx context.Context, accountID string, userID string, groups []string) error
	GroupValidation(ctx context.Context, accountId string, groups []string) (bool, error)
	GetValidatedPeers(ctx context.Context, accountID string) (map[string]struct{}, error)
	SyncAndMarkPeer(ctx context.Context, accountID string, peerPubKey string, meta nbpeer.PeerSystemMeta, realIP net.IP) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error)
	OnPeerDisconnected(ctx context.Context, accountID string, peerPubKey string) error
	SyncPeerMeta(ctx context.Context, peerPubKey string, meta nbpeer.PeerSystemMeta) error
	FindExistingPostureCheck(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error)
	GetAccountIDForPeerKey(ctx context.Context, peerKey string) (string, error)
	GetAccountSettings(ctx context.Context, accountID string, userID string) (*types.Settings, error)
	DeleteSetupKey(ctx context.Context, accountID, userID, keyID string) error
	UpdateAccountPeers(ctx context.Context, accountID string)
}

type DefaultAccountManager struct {
	Store store.Store
	// cacheMux and cacheLoading helps to make sure that only a single cache reload runs at a time per accountID
	cacheMux sync.Mutex
	// cacheLoading keeps the accountIDs that are currently reloading. The accountID has to be removed once cache has been reloaded
	cacheLoading         map[string]chan struct{}
	peersUpdateManager   *PeersUpdateManager
	idpManager           idp.Manager
	cacheManager         cache.CacheInterface[[]*idp.UserData]
	externalCacheManager ExternalCacheManager
	ctx                  context.Context
	eventStore           activity.Store
	geo                  geolocation.Geolocation

	requestBuffer *AccountRequestBuffer

	// singleAccountMode indicates whether the instance has a single account.
	// If true, then every new user will end up under the same account.
	// This value will be set to false if management service has more than one account.
	singleAccountMode bool
	// singleAccountModeDomain is a domain to use in singleAccountMode setup
	singleAccountModeDomain string
	// dnsDomain is used for peer resolution. This is appended to the peer's name
	dnsDomain       string
	peerLoginExpiry Scheduler

	peerInactivityExpiry Scheduler

	// userDeleteFromIDPEnabled allows to delete user from IDP when user is deleted from account
	userDeleteFromIDPEnabled bool

	integratedPeerValidator integrated_validator.IntegratedValidator

	metrics telemetry.AppMetrics
}

// getJWTGroupsChanges calculates the changes needed to sync a user's JWT groups.
// Returns a bool indicating if there are changes in the JWT group membership, the updated user AutoGroups,
// newly groups to create and an error if any occurred.
func (am *DefaultAccountManager) getJWTGroupsChanges(user *types.User, groups []*types.Group, groupNames []string) (bool, []string, []*types.Group, error) {
	existedGroupsByName := make(map[string]*types.Group)
	for _, group := range groups {
		existedGroupsByName[group.Name] = group
	}

	newUserAutoGroups, jwtGroupsMap := separateGroups(user.AutoGroups, groups)

	groupsToAdd := util.Difference(groupNames, maps.Keys(jwtGroupsMap))
	groupsToRemove := util.Difference(maps.Keys(jwtGroupsMap), groupNames)

	// If no groups are added or removed, we should not sync account
	if len(groupsToAdd) == 0 && len(groupsToRemove) == 0 {
		return false, nil, nil, nil
	}

	newGroupsToCreate := make([]*types.Group, 0)

	var modified bool
	for _, name := range groupsToAdd {
		group, exists := existedGroupsByName[name]
		if !exists {
			group = &types.Group{
				ID:        xid.New().String(),
				AccountID: user.AccountID,
				Name:      name,
				Issued:    types.GroupIssuedJWT,
			}
			newGroupsToCreate = append(newGroupsToCreate, group)
		}
		if group.Issued == types.GroupIssuedJWT {
			newUserAutoGroups = append(newUserAutoGroups, group.ID)
			modified = true
		}
	}

	for name, id := range jwtGroupsMap {
		if !slices.Contains(groupsToRemove, name) {
			newUserAutoGroups = append(newUserAutoGroups, id)
			continue
		}
		modified = true
	}

	return modified, newUserAutoGroups, newGroupsToCreate, nil
}

// BuildManager creates a new DefaultAccountManager with a provided Store
func BuildManager(
	ctx context.Context,
	store store.Store,
	peersUpdateManager *PeersUpdateManager,
	idpManager idp.Manager,
	singleAccountModeDomain string,
	dnsDomain string,
	eventStore activity.Store,
	geo geolocation.Geolocation,
	userDeleteFromIDPEnabled bool,
	integratedPeerValidator integrated_validator.IntegratedValidator,
	metrics telemetry.AppMetrics,
) (*DefaultAccountManager, error) {
	am := &DefaultAccountManager{
		Store:                    store,
		geo:                      geo,
		peersUpdateManager:       peersUpdateManager,
		idpManager:               idpManager,
		ctx:                      context.Background(),
		cacheMux:                 sync.Mutex{},
		cacheLoading:             map[string]chan struct{}{},
		dnsDomain:                dnsDomain,
		eventStore:               eventStore,
		peerLoginExpiry:          NewDefaultScheduler(),
		peerInactivityExpiry:     NewDefaultScheduler(),
		userDeleteFromIDPEnabled: userDeleteFromIDPEnabled,
		integratedPeerValidator:  integratedPeerValidator,
		metrics:                  metrics,
		requestBuffer:            NewAccountRequestBuffer(ctx, store),
	}
	allAccounts := store.GetAllAccounts(ctx)
	// enable single account mode only if configured by user and number of existing accounts is not grater than 1
	am.singleAccountMode = singleAccountModeDomain != "" && len(allAccounts) <= 1
	if am.singleAccountMode {
		if !isDomainValid(singleAccountModeDomain) {
			return nil, status.Errorf(status.InvalidArgument, "invalid domain \"%s\" provided for a single account mode. Please review your input for --single-account-mode-domain", singleAccountModeDomain)
		}
		am.singleAccountModeDomain = singleAccountModeDomain
		log.WithContext(ctx).Infof("single account mode enabled, accounts number %d", len(allAccounts))
	} else {
		log.WithContext(ctx).Infof("single account mode disabled, accounts number %d", len(allAccounts))
	}

	// if account doesn't have a default group
	// we create 'all' group and add all peers into it
	// also we create default rule with source as destination
	for _, account := range allAccounts {
		shouldSave := false

		_, err := account.GetGroupAll()
		if err != nil {
			if err := addAllGroup(account); err != nil {
				return nil, err
			}
			shouldSave = true
		}

		if shouldSave {
			err = store.SaveAccount(ctx, account)
			if err != nil {
				return nil, err
			}
		}
	}

	goCacheClient := gocache.New(CacheExpirationMax, 30*time.Minute)
	goCacheStore := cacheStore.NewGoCache(goCacheClient)
	am.cacheManager = cache.NewLoadable[[]*idp.UserData](am.loadAccount, cache.New[[]*idp.UserData](goCacheStore))

	// TODO: what is max expiration time? Should be quite long
	am.externalCacheManager = cache.New[*idp.UserData](
		cacheStore.NewGoCache(goCacheClient),
	)

	if !isNil(am.idpManager) {
		go func() {
			err := am.warmupIDPCache(ctx)
			if err != nil {
				log.WithContext(ctx).Warnf("failed warming up cache due to error: %v", err)
				// todo retry?
				return
			}
		}()
	}

	am.integratedPeerValidator.SetPeerInvalidationListener(func(accountID string) {
		am.onPeersInvalidated(ctx, accountID)
	})

	return am, nil
}

func (am *DefaultAccountManager) GetExternalCacheManager() ExternalCacheManager {
	return am.externalCacheManager
}

func (am *DefaultAccountManager) GetIdpManager() idp.Manager {
	return am.idpManager
}

// UpdateAccountSettings updates Account settings.
// Only users with role UserRoleAdmin can update the account.
// User that performs the update has to belong to the account.
// Returns an updated Account
func (am *DefaultAccountManager) UpdateAccountSettings(ctx context.Context, accountID, userID string, newSettings *types.Settings) (*types.Account, error) {
	halfYearLimit := 180 * 24 * time.Hour
	if newSettings.PeerLoginExpiration > halfYearLimit {
		return nil, status.Errorf(status.InvalidArgument, "peer login expiration can't be larger than 180 days")
	}

	if newSettings.PeerLoginExpiration < time.Hour {
		return nil, status.Errorf(status.InvalidArgument, "peer login expiration can't be smaller than one hour")
	}

	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.HasAdminPower() {
		return nil, status.Errorf(status.PermissionDenied, "user is not allowed to update account")
	}

	err = am.integratedPeerValidator.ValidateExtraSettings(ctx, newSettings.Extra, account.Settings.Extra, account.Peers, userID, accountID)
	if err != nil {
		return nil, err
	}

	oldSettings := account.Settings
	if oldSettings.PeerLoginExpirationEnabled != newSettings.PeerLoginExpirationEnabled {
		event := activity.AccountPeerLoginExpirationEnabled
		if !newSettings.PeerLoginExpirationEnabled {
			event = activity.AccountPeerLoginExpirationDisabled
			am.peerLoginExpiry.Cancel(ctx, []string{accountID})
		} else {
			am.checkAndSchedulePeerLoginExpiration(ctx, accountID)
		}
		am.StoreEvent(ctx, userID, accountID, accountID, event, nil)
	}

	if oldSettings.PeerLoginExpiration != newSettings.PeerLoginExpiration {
		am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountPeerLoginExpirationDurationUpdated, nil)
		am.checkAndSchedulePeerLoginExpiration(ctx, accountID)
	}

	updateAccountPeers := false
	if oldSettings.RoutingPeerDNSResolutionEnabled != newSettings.RoutingPeerDNSResolutionEnabled {
		if newSettings.RoutingPeerDNSResolutionEnabled {
			am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountRoutingPeerDNSResolutionEnabled, nil)
		} else {
			am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountRoutingPeerDNSResolutionDisabled, nil)
		}
		updateAccountPeers = true
		account.Network.Serial++
	}

	err = am.handleInactivityExpirationSettings(ctx, oldSettings, newSettings, userID, accountID)
	if err != nil {
		return nil, err
	}

	err = am.handleGroupsPropagationSettings(ctx, oldSettings, newSettings, userID, accountID)
	if err != nil {
		return nil, fmt.Errorf("groups propagation failed: %w", err)
	}

	updatedAccount := account.UpdateSettings(newSettings)

	err = am.Store.SaveAccount(ctx, account)
	if err != nil {
		return nil, err
	}

	if updateAccountPeers {
		go am.UpdateAccountPeers(ctx, accountID)
	}

	return updatedAccount, nil
}

func (am *DefaultAccountManager) handleGroupsPropagationSettings(ctx context.Context, oldSettings, newSettings *types.Settings, userID, accountID string) error {
	if oldSettings.GroupsPropagationEnabled != newSettings.GroupsPropagationEnabled {
		if newSettings.GroupsPropagationEnabled {
			am.StoreEvent(ctx, userID, accountID, accountID, activity.UserGroupPropagationEnabled, nil)
			// Todo: retroactively add user groups to all peers
		} else {
			am.StoreEvent(ctx, userID, accountID, accountID, activity.UserGroupPropagationDisabled, nil)
		}
	}

	return nil
}

func (am *DefaultAccountManager) handleInactivityExpirationSettings(ctx context.Context, oldSettings, newSettings *types.Settings, userID, accountID string) error {
	if newSettings.PeerInactivityExpirationEnabled {
		if oldSettings.PeerInactivityExpiration != newSettings.PeerInactivityExpiration {
			oldSettings.PeerInactivityExpiration = newSettings.PeerInactivityExpiration

			am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountPeerInactivityExpirationDurationUpdated, nil)
			am.checkAndSchedulePeerInactivityExpiration(ctx, accountID)
		}
	} else {
		if oldSettings.PeerInactivityExpirationEnabled != newSettings.PeerInactivityExpirationEnabled {
			event := activity.AccountPeerInactivityExpirationEnabled
			if !newSettings.PeerInactivityExpirationEnabled {
				event = activity.AccountPeerInactivityExpirationDisabled
				am.peerInactivityExpiry.Cancel(ctx, []string{accountID})
			} else {
				am.checkAndSchedulePeerInactivityExpiration(ctx, accountID)
			}
			am.StoreEvent(ctx, userID, accountID, accountID, event, nil)
		}
	}

	return nil
}

func (am *DefaultAccountManager) peerLoginExpirationJob(ctx context.Context, accountID string) func() (time.Duration, bool) {
	return func() (time.Duration, bool) {
		unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
		defer unlock()

		expiredPeers, err := am.getExpiredPeers(ctx, accountID)
		if err != nil {
			return peerSchedulerRetryInterval, true
		}

		var peerIDs []string
		for _, peer := range expiredPeers {
			peerIDs = append(peerIDs, peer.ID)
		}

		log.WithContext(ctx).Debugf("discovered %d peers to expire for account %s", len(peerIDs), accountID)

		if err := am.expireAndUpdatePeers(ctx, accountID, expiredPeers); err != nil {
			log.WithContext(ctx).Errorf("failed updating account peers while expiring peers for account %s", accountID)
			return peerSchedulerRetryInterval, true
		}

		return am.getNextPeerExpiration(ctx, accountID)
	}
}

func (am *DefaultAccountManager) checkAndSchedulePeerLoginExpiration(ctx context.Context, accountID string) {
	am.peerLoginExpiry.Cancel(ctx, []string{accountID})
	if nextRun, ok := am.getNextPeerExpiration(ctx, accountID); ok {
		go am.peerLoginExpiry.Schedule(ctx, nextRun, accountID, am.peerLoginExpirationJob(ctx, accountID))
	}
}

// peerInactivityExpirationJob marks login expired for all inactive peers and returns the minimum duration in which the next peer of the account will expire by inactivity if found
func (am *DefaultAccountManager) peerInactivityExpirationJob(ctx context.Context, accountID string) func() (time.Duration, bool) {
	return func() (time.Duration, bool) {
		unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
		defer unlock()

		inactivePeers, err := am.getInactivePeers(ctx, accountID)
		if err != nil {
			log.WithContext(ctx).Errorf("failed getting inactive peers for account %s", accountID)
			return peerSchedulerRetryInterval, true
		}

		var peerIDs []string
		for _, peer := range inactivePeers {
			peerIDs = append(peerIDs, peer.ID)
		}

		log.Debugf("discovered %d peers to expire for account %s", len(peerIDs), accountID)

		if err := am.expireAndUpdatePeers(ctx, accountID, inactivePeers); err != nil {
			log.Errorf("failed updating account peers while expiring peers for account %s", accountID)
			return peerSchedulerRetryInterval, true
		}

		return am.getNextInactivePeerExpiration(ctx, accountID)
	}
}

// checkAndSchedulePeerInactivityExpiration periodically checks for inactive peers to end their sessions
func (am *DefaultAccountManager) checkAndSchedulePeerInactivityExpiration(ctx context.Context, accountID string) {
	am.peerInactivityExpiry.Cancel(ctx, []string{accountID})
	if nextRun, ok := am.getNextInactivePeerExpiration(ctx, accountID); ok {
		go am.peerInactivityExpiry.Schedule(ctx, nextRun, accountID, am.peerInactivityExpirationJob(ctx, accountID))
	}
}

// newAccount creates a new Account with a generated ID and generated default setup keys.
// If ID is already in use (due to collision) we try one more time before returning error
func (am *DefaultAccountManager) newAccount(ctx context.Context, userID, domain string) (*types.Account, error) {
	for i := 0; i < 2; i++ {
		accountId := xid.New().String()

		_, err := am.Store.GetAccount(ctx, accountId)
		statusErr, _ := status.FromError(err)
		switch {
		case err == nil:
			log.WithContext(ctx).Warnf("an account with ID already exists, retrying...")
			continue
		case statusErr.Type() == status.NotFound:
			newAccount := newAccountWithId(ctx, accountId, userID, domain)
			am.StoreEvent(ctx, userID, newAccount.Id, accountId, activity.AccountCreated, nil)
			return newAccount, nil
		default:
			return nil, err
		}
	}

	return nil, status.Errorf(status.Internal, "error while creating new account")
}

func (am *DefaultAccountManager) warmupIDPCache(ctx context.Context) error {
	userData, err := am.idpManager.GetAllAccounts(ctx)
	if err != nil {
		return err
	}
	log.WithContext(ctx).Infof("%d entries received from IdP management", len(userData))

	// If the Identity Provider does not support writing AppMetadata,
	// in cases like this, we expect it to return all users in an "unset" field.
	// We iterate over the users in the "unset" field, look up their AccountID in our store, and
	// update their AppMetadata with the AccountID.
	if unsetData, ok := userData[idp.UnsetAccountID]; ok {
		for _, user := range unsetData {
			accountID, err := am.Store.GetAccountByUser(ctx, user.ID)
			if err == nil {
				data := userData[accountID.Id]
				if data == nil {
					data = make([]*idp.UserData, 0, 1)
				}

				user.AppMetadata.WTAccountID = accountID.Id

				userData[accountID.Id] = append(data, user)
			}
		}
	}
	delete(userData, idp.UnsetAccountID)

	rcvdUsers := 0
	for accountID, users := range userData {
		rcvdUsers += len(users)
		err = am.cacheManager.Set(am.ctx, accountID, users, cacheStore.WithExpiration(cacheEntryExpiration()))
		if err != nil {
			return err
		}
	}
	log.WithContext(ctx).Infof("warmed up IDP cache with %d entries for %d accounts", rcvdUsers, len(userData))
	return nil
}

// DeleteAccount deletes an account and all its users from local store and from the remote IDP if the requester is an admin and account owner
func (am *DefaultAccountManager) DeleteAccount(ctx context.Context, accountID, userID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()
	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return err
	}

	if !user.HasAdminPower() {
		return status.Errorf(status.PermissionDenied, "user is not allowed to delete account")
	}

	if user.Role != types.UserRoleOwner {
		return status.Errorf(status.PermissionDenied, "user is not allowed to delete account. Only account owner can delete account")
	}
	for _, otherUser := range account.Users {
		if otherUser.IsServiceUser {
			continue
		}

		if otherUser.Id == userID {
			continue
		}

		deleteUserErr := am.deleteRegularUser(ctx, account, userID, otherUser.Id)
		if deleteUserErr != nil {
			return deleteUserErr
		}
	}

	err = am.deleteRegularUser(ctx, account, userID, userID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed deleting user %s. error: %s", userID, err)
		return err
	}

	err = am.Store.DeleteAccount(ctx, account)
	if err != nil {
		log.WithContext(ctx).Errorf("failed deleting account %s. error: %s", accountID, err)
		return err
	}
	// cancel peer login expiry job
	am.peerLoginExpiry.Cancel(ctx, []string{account.Id})

	log.WithContext(ctx).Debugf("account %s deleted", accountID)
	return nil
}

// AccountExists checks if an account exists.
func (am *DefaultAccountManager) AccountExists(ctx context.Context, accountID string) (bool, error) {
	return am.Store.AccountExists(ctx, store.LockingStrengthShare, accountID)
}

// GetAccountIDByUserID retrieves the account ID based on the userID provided.
// If user does have an account, it returns the user's account ID.
// If the user doesn't have an account, it creates one using the provided domain.
// Returns the account ID or an error if none is found or created.
func (am *DefaultAccountManager) GetAccountIDByUserID(ctx context.Context, userID, domain string) (string, error) {
	if userID == "" {
		return "", status.Errorf(status.NotFound, "no valid userID provided")
	}

	accountID, err := am.Store.GetAccountIDByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Type() == status.NotFound {
			account, err := am.GetOrCreateAccountByUser(ctx, userID, domain)
			if err != nil {
				return "", status.Errorf(status.NotFound, "account not found or created for user id: %s", userID)
			}

			if err = am.addAccountIDToIDPAppMeta(ctx, userID, account.Id); err != nil {
				return "", err
			}
			return account.Id, nil
		}
		return "", err
	}
	return accountID, nil
}

func isNil(i idp.Manager) bool {
	return i == nil || reflect.ValueOf(i).IsNil()
}

// addAccountIDToIDPAppMeta update user's  app metadata in idp manager
func (am *DefaultAccountManager) addAccountIDToIDPAppMeta(ctx context.Context, userID string, accountID string) error {
	if !isNil(am.idpManager) {
		accountUsers, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthShare, accountID)
		if err != nil {
			return err
		}
		cachedAccount := &types.Account{
			Id:    accountID,
			Users: make(map[string]*types.User),
		}
		for _, user := range accountUsers {
			cachedAccount.Users[user.Id] = user
		}

		// user can be nil if it wasn't found (e.g., just created)
		user, err := am.lookupUserInCache(ctx, userID, cachedAccount)
		if err != nil {
			return err
		}

		if user != nil && user.AppMetadata.WTAccountID == accountID {
			// it was already set, so we skip the unnecessary update
			log.WithContext(ctx).Debugf("skipping IDP App Meta update because accountID %s has been already set for user %s",
				accountID, userID)
			return nil
		}

		err = am.idpManager.UpdateUserAppMetadata(ctx, userID, idp.AppMetadata{WTAccountID: accountID})
		if err != nil {
			return status.Errorf(status.Internal, "updating user's app metadata failed with: %v", err)
		}
		// refresh cache to reflect the update
		_, err = am.refreshCache(ctx, accountID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (am *DefaultAccountManager) loadAccount(ctx context.Context, accountID interface{}) ([]*idp.UserData, error) {
	log.WithContext(ctx).Debugf("account %s not found in cache, reloading", accountID)
	accountIDString := fmt.Sprintf("%v", accountID)

	account, err := am.Store.GetAccount(ctx, accountIDString)
	if err != nil {
		return nil, err
	}

	userData, err := am.idpManager.GetAccount(ctx, accountIDString)
	if err != nil {
		return nil, err
	}
	log.WithContext(ctx).Debugf("%d entries received from IdP management", len(userData))

	dataMap := make(map[string]*idp.UserData, len(userData))
	for _, datum := range userData {
		dataMap[datum.ID] = datum
	}

	matchedUserData := make([]*idp.UserData, 0)
	for _, user := range account.Users {
		if user.IsServiceUser {
			continue
		}
		datum, ok := dataMap[user.Id]
		if !ok {
			log.WithContext(ctx).Warnf("user %s not found in IDP", user.Id)
			continue
		}
		matchedUserData = append(matchedUserData, datum)
	}
	return matchedUserData, nil
}

func (am *DefaultAccountManager) lookupUserInCacheByEmail(ctx context.Context, email string, accountID string) (*idp.UserData, error) {
	data, err := am.getAccountFromCache(ctx, accountID, false)
	if err != nil {
		return nil, err
	}

	for _, datum := range data {
		if datum.Email == email {
			return datum, nil
		}
	}

	return nil, nil //nolint:nilnil
}

// lookupUserInCache looks up user in the IdP cache and returns it. If the user wasn't found, the function returns nil
func (am *DefaultAccountManager) lookupUserInCache(ctx context.Context, userID string, account *types.Account) (*idp.UserData, error) {
	users := make(map[string]userLoggedInOnce, len(account.Users))
	// ignore service users and users provisioned by integrations than are never logged in
	for _, user := range account.Users {
		if user.IsServiceUser {
			continue
		}
		if user.Issued == types.UserIssuedIntegration {
			continue
		}
		users[user.Id] = userLoggedInOnce(!user.GetLastLogin().IsZero())
	}
	log.WithContext(ctx).Debugf("looking up user %s of account %s in cache", userID, account.Id)
	userData, err := am.lookupCache(ctx, users, account.Id)
	if err != nil {
		return nil, err
	}

	for _, datum := range userData {
		if datum.ID == userID {
			return datum, nil
		}
	}

	// add extra check on external cache manager. We may get to this point when the user is not yet findable in IDP,
	// or it didn't have its metadata updated with am.addAccountIDToIDPAppMeta
	user, err := account.FindUser(userID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed finding user %s in account %s", userID, account.Id)
		return nil, err
	}

	key := user.IntegrationReference.CacheKey(account.Id, userID)
	ud, err := am.externalCacheManager.Get(am.ctx, key)
	if err != nil {
		log.WithContext(ctx).Debugf("failed to get externalCache for key: %s, error: %s", key, err)
	}

	return ud, nil
}

func (am *DefaultAccountManager) refreshCache(ctx context.Context, accountID string) ([]*idp.UserData, error) {
	return am.getAccountFromCache(ctx, accountID, true)
}

// getAccountFromCache returns user data for a given account ensuring that cache load happens only once
func (am *DefaultAccountManager) getAccountFromCache(ctx context.Context, accountID string, forceReload bool) ([]*idp.UserData, error) {
	am.cacheMux.Lock()
	loadingChan := am.cacheLoading[accountID]
	if loadingChan == nil {
		loadingChan = make(chan struct{})
		am.cacheLoading[accountID] = loadingChan
		am.cacheMux.Unlock()

		defer func() {
			am.cacheMux.Lock()
			delete(am.cacheLoading, accountID)
			close(loadingChan)
			am.cacheMux.Unlock()
		}()

		if forceReload {
			err := am.cacheManager.Delete(am.ctx, accountID)
			if err != nil {
				return nil, err
			}
		}

		return am.cacheManager.Get(am.ctx, accountID)
	}
	am.cacheMux.Unlock()

	log.WithContext(ctx).Debugf("one request to get account %s is already running", accountID)

	select {
	case <-loadingChan:
		// channel has been closed meaning cache was loaded => simply return from cache
		return am.cacheManager.Get(am.ctx, accountID)
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("timeout while waiting for account %s cache to reload", accountID)
	}
}

func (am *DefaultAccountManager) lookupCache(ctx context.Context, accountUsers map[string]userLoggedInOnce, accountID string) ([]*idp.UserData, error) {
	var data []*idp.UserData
	var err error

	maxAttempts := 2

	data, err = am.getAccountFromCache(ctx, accountID, false)
	if err != nil {
		return nil, err
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if am.isCacheFresh(ctx, accountUsers, data) {
			return data, nil
		}

		if attempt > 1 {
			time.Sleep(200 * time.Millisecond)
		}

		log.WithContext(ctx).Infof("refreshing cache for account %s", accountID)
		data, err = am.refreshCache(ctx, accountID)
		if err != nil {
			return nil, err
		}

		if attempt == maxAttempts {
			log.WithContext(ctx).Warnf("cache for account %s reached maximum refresh attempts (%d)", accountID, maxAttempts)
		}
	}

	return data, nil
}

// isCacheFresh checks if the cache is refreshed already by comparing the accountUsers with the cache data by user count and user invite status
func (am *DefaultAccountManager) isCacheFresh(ctx context.Context, accountUsers map[string]userLoggedInOnce, data []*idp.UserData) bool {
	userDataMap := make(map[string]*idp.UserData, len(data))
	for _, datum := range data {
		userDataMap[datum.ID] = datum
	}

	// the accountUsers ID list of non integration users from store, we check if cache has all of them
	// as result of for loop knownUsersCount will have number of users are not presented in the cashed
	knownUsersCount := len(accountUsers)
	for user, loggedInOnce := range accountUsers {
		if datum, ok := userDataMap[user]; ok {
			// check if the matching user data has a pending invite and if the user has logged in once, forcing the cache to be refreshed
			if datum.AppMetadata.WTPendingInvite != nil && *datum.AppMetadata.WTPendingInvite && loggedInOnce == true { //nolint:gosimple
				log.WithContext(ctx).Infof("user %s has a pending invite and has logged in once, cache invalid", user)
				return false
			}
			knownUsersCount--
			continue
		}
		log.WithContext(ctx).Debugf("cache doesn't know about %s user", user)
	}

	// if we know users that are not yet in cache more likely cache is outdated
	if knownUsersCount > 0 {
		log.WithContext(ctx).Infof("cache invalid. Users unknown to the cache: %d", knownUsersCount)
		return false
	}

	return true
}

func (am *DefaultAccountManager) removeUserFromCache(ctx context.Context, accountID, userID string) error {
	data, err := am.getAccountFromCache(ctx, accountID, false)
	if err != nil {
		return err
	}

	for i, datum := range data {
		if datum.ID == userID {
			data = append(data[:i], data[i+1:]...)
			break
		}
	}

	return am.cacheManager.Set(am.ctx, accountID, data, cacheStore.WithExpiration(cacheEntryExpiration()))
}

// updateAccountDomainAttributesIfNotUpToDate updates the account domain attributes if they are not up to date and then, saves the account changes
func (am *DefaultAccountManager) updateAccountDomainAttributesIfNotUpToDate(ctx context.Context, accountID string, claims jwtclaims.AuthorizationClaims,
	primaryDomain bool,
) error {
	if claims.Domain == "" {
		log.WithContext(ctx).Errorf("claims don't contain a valid domain, skipping domain attributes update. Received claims: %v", claims)
		return nil
	}

	unlockAccount := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlockAccount()

	accountDomain, domainCategory, err := am.Store.GetAccountDomainAndCategory(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error getting account domain and category: %v", err)
		return err
	}

	if domainIsUpToDate(accountDomain, domainCategory, claims) {
		return nil
	}

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, claims.UserId)
	if err != nil {
		log.WithContext(ctx).Errorf("error getting user: %v", err)
		return err
	}

	newDomain := accountDomain
	newCategoty := domainCategory

	lowerDomain := strings.ToLower(claims.Domain)
	if accountDomain != lowerDomain && user.HasAdminPower() {
		newDomain = lowerDomain
	}

	if accountDomain == lowerDomain {
		newCategoty = claims.DomainCategory
	}

	return am.Store.UpdateAccountDomainAttributes(ctx, accountID, newDomain, newCategoty, primaryDomain)
}

// handleExistingUserAccount handles existing User accounts and update its domain attributes.
// If there is no primary domain account yet, we set the account as primary for the domain. Otherwise,
// we compare the account's ID with the domain account ID, and if they don't match, we set the account as
// non-primary account for the domain. We don't merge accounts at this stage, because of cases when a domain
// was previously unclassified or classified as public so N users that logged int that time, has they own account
// and peers that shouldn't be lost.
func (am *DefaultAccountManager) handleExistingUserAccount(
	ctx context.Context,
	userAccountID string,
	domainAccountID string,
	claims jwtclaims.AuthorizationClaims,
) error {
	primaryDomain := domainAccountID == "" || userAccountID == domainAccountID
	err := am.updateAccountDomainAttributesIfNotUpToDate(ctx, userAccountID, claims, primaryDomain)
	if err != nil {
		return err
	}

	// we should register the account ID to this user's metadata in our IDP manager
	err = am.addAccountIDToIDPAppMeta(ctx, claims.UserId, userAccountID)
	if err != nil {
		return err
	}

	return nil
}

// addNewPrivateAccount validates if there is an existing primary account for the domain, if so it adds the new user to that account,
// otherwise it will create a new account and make it primary account for the domain.
func (am *DefaultAccountManager) addNewPrivateAccount(ctx context.Context, domainAccountID string, claims jwtclaims.AuthorizationClaims) (string, error) {
	if claims.UserId == "" {
		return "", fmt.Errorf("user ID is empty")
	}

	lowerDomain := strings.ToLower(claims.Domain)

	newAccount, err := am.newAccount(ctx, claims.UserId, lowerDomain)
	if err != nil {
		return "", err
	}

	newAccount.Domain = lowerDomain
	newAccount.DomainCategory = claims.DomainCategory
	newAccount.IsDomainPrimaryAccount = true

	err = am.Store.SaveAccount(ctx, newAccount)
	if err != nil {
		return "", err
	}

	err = am.addAccountIDToIDPAppMeta(ctx, claims.UserId, newAccount.Id)
	if err != nil {
		return "", err
	}

	am.StoreEvent(ctx, claims.UserId, claims.UserId, newAccount.Id, activity.UserJoined, nil)

	return newAccount.Id, nil
}

func (am *DefaultAccountManager) addNewUserToDomainAccount(ctx context.Context, domainAccountID string, claims jwtclaims.AuthorizationClaims) (string, error) {
	unlockAccount := am.Store.AcquireWriteLockByUID(ctx, domainAccountID)
	defer unlockAccount()

	usersMap := make(map[string]*types.User)
	usersMap[claims.UserId] = types.NewRegularUser(claims.UserId)
	err := am.Store.SaveUsers(domainAccountID, usersMap)
	if err != nil {
		return "", err
	}

	err = am.addAccountIDToIDPAppMeta(ctx, claims.UserId, domainAccountID)
	if err != nil {
		return "", err
	}

	am.StoreEvent(ctx, claims.UserId, claims.UserId, domainAccountID, activity.UserJoined, nil)

	return domainAccountID, nil
}

// redeemInvite checks whether user has been invited and redeems the invite
func (am *DefaultAccountManager) redeemInvite(ctx context.Context, accountID string, userID string) error {
	// only possible with the enabled IdP manager
	if am.idpManager == nil {
		log.WithContext(ctx).Warnf("invites only work with enabled IdP manager")
		return nil
	}

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	user, err := am.lookupUserInCache(ctx, userID, account)
	if err != nil {
		return err
	}

	if user == nil {
		return status.Errorf(status.NotFound, "user %s not found in the IdP", userID)
	}

	if user.AppMetadata.WTPendingInvite != nil && *user.AppMetadata.WTPendingInvite {
		log.WithContext(ctx).Infof("redeeming invite for user %s account %s", userID, account.Id)
		// User has already logged in, meaning that IdP should have set wt_pending_invite to false.
		// Our job is to just reload cache.
		go func() {
			_, err = am.refreshCache(ctx, account.Id)
			if err != nil {
				log.WithContext(ctx).Warnf("failed reloading cache when redeeming user %s under account %s", userID, account.Id)
				return
			}
			log.WithContext(ctx).Debugf("user %s of account %s redeemed invite", user.ID, account.Id)
			am.StoreEvent(ctx, userID, userID, account.Id, activity.UserJoined, nil)
		}()
	}

	return nil
}

// MarkPATUsed marks a personal access token as used
func (am *DefaultAccountManager) MarkPATUsed(ctx context.Context, tokenID string) error {

	user, err := am.Store.GetUserByTokenID(ctx, tokenID)
	if err != nil {
		return err
	}

	account, err := am.Store.GetAccountByUser(ctx, user.Id)
	if err != nil {
		return err
	}

	unlock := am.Store.AcquireWriteLockByUID(ctx, account.Id)
	defer unlock()

	account, err = am.Store.GetAccountByUser(ctx, user.Id)
	if err != nil {
		return err
	}

	pat, ok := account.Users[user.Id].PATs[tokenID]
	if !ok {
		return fmt.Errorf("token not found")
	}

	pat.LastUsed = util.ToPtr(time.Now().UTC())

	return am.Store.SaveAccount(ctx, account)
}

// GetAccount returns an account associated with this account ID.
func (am *DefaultAccountManager) GetAccount(ctx context.Context, accountID string) (*types.Account, error) {
	return am.Store.GetAccount(ctx, accountID)
}

// GetAccountFromPAT returns Account and User associated with a personal access token
func (am *DefaultAccountManager) GetAccountFromPAT(ctx context.Context, token string) (*types.Account, *types.User, *types.PersonalAccessToken, error) {
	if len(token) != types.PATLength {
		return nil, nil, nil, fmt.Errorf("token has wrong length")
	}

	prefix := token[:len(types.PATPrefix)]
	if prefix != types.PATPrefix {
		return nil, nil, nil, fmt.Errorf("token has wrong prefix")
	}
	secret := token[len(types.PATPrefix) : len(types.PATPrefix)+types.PATSecretLength]
	encodedChecksum := token[len(types.PATPrefix)+types.PATSecretLength : len(types.PATPrefix)+types.PATSecretLength+types.PATChecksumLength]

	verificationChecksum, err := base62.Decode(encodedChecksum)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("token checksum decoding failed: %w", err)
	}

	secretChecksum := crc32.ChecksumIEEE([]byte(secret))
	if secretChecksum != verificationChecksum {
		return nil, nil, nil, fmt.Errorf("token checksum does not match")
	}

	hashedToken := sha256.Sum256([]byte(token))
	encodedHashedToken := b64.StdEncoding.EncodeToString(hashedToken[:])
	tokenID, err := am.Store.GetTokenIDByHashedToken(ctx, encodedHashedToken)
	if err != nil {
		return nil, nil, nil, err
	}

	user, err := am.Store.GetUserByTokenID(ctx, tokenID)
	if err != nil {
		return nil, nil, nil, err
	}

	account, err := am.Store.GetAccountByUser(ctx, user.Id)
	if err != nil {
		return nil, nil, nil, err
	}

	pat := user.PATs[tokenID]
	if pat == nil {
		return nil, nil, nil, fmt.Errorf("personal access token not found")
	}

	return account, user, pat, nil
}

// GetAccountByID returns an account associated with this account ID.
func (am *DefaultAccountManager) GetAccountByID(ctx context.Context, accountID string, userID string) (*types.Account, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.Errorf(status.PermissionDenied, "the user has no permission to access account data")
	}

	return am.Store.GetAccount(ctx, accountID)
}

// GetAccountIDFromToken returns an account ID associated with this token.
func (am *DefaultAccountManager) GetAccountIDFromToken(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error) {
	if claims.UserId == "" {
		return "", "", errors.New(emptyUserID)
	}
	if am.singleAccountMode && am.singleAccountModeDomain != "" {
		// This section is mostly related to self-hosted installations.
		// We override incoming domain claims to group users under a single account.
		claims.Domain = am.singleAccountModeDomain
		claims.DomainCategory = types.PrivateCategory
		log.WithContext(ctx).Debugf("overriding JWT Domain and DomainCategory claims since single account mode is enabled")
	}

	accountID, err := am.getAccountIDWithAuthorizationClaims(ctx, claims)
	if err != nil {
		return "", "", err
	}

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, claims.UserId)
	if err != nil {
		// this is not really possible because we got an account by user ID
		return "", "", status.Errorf(status.NotFound, "user %s not found", claims.UserId)
	}

	if user.AccountID != accountID {
		return "", "", status.Errorf(status.PermissionDenied, "user %s is not part of the account %s", claims.UserId, accountID)
	}

	if !user.IsServiceUser && claims.Invited {
		err = am.redeemInvite(ctx, accountID, user.Id)
		if err != nil {
			return "", "", err
		}
	}

	if err = am.syncJWTGroups(ctx, accountID, claims); err != nil {
		return "", "", err
	}

	return accountID, user.Id, nil
}

// syncJWTGroups processes the JWT groups for a user, updates the account based on the groups,
// and propagates changes to peers if group propagation is enabled.
func (am *DefaultAccountManager) syncJWTGroups(ctx context.Context, accountID string, claims jwtclaims.AuthorizationClaims) error {
	if claim, exists := claims.Raw[jwtclaims.IsToken]; exists {
		if isToken, ok := claim.(bool); ok && isToken {
			return nil
		}
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return err
	}

	if settings == nil || !settings.JWTGroupsEnabled {
		return nil
	}

	if settings.JWTGroupsClaimName == "" {
		log.WithContext(ctx).Debugf("JWT groups are enabled but no claim name is set")
		return nil
	}

	jwtGroupsNames := extractJWTGroups(ctx, settings.JWTGroupsClaimName, claims)

	unlockAccount := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer func() {
		if unlockAccount != nil {
			unlockAccount()
		}
	}()

	var addNewGroups []string
	var removeOldGroups []string
	var hasChanges bool
	var user *types.User
	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		user, err = transaction.GetUserByUserID(ctx, store.LockingStrengthShare, claims.UserId)
		if err != nil {
			return fmt.Errorf("error getting user: %w", err)
		}

		groups, err := transaction.GetAccountGroups(ctx, store.LockingStrengthShare, accountID)
		if err != nil {
			return fmt.Errorf("error getting account groups: %w", err)
		}

		changed, updatedAutoGroups, newGroupsToCreate, err := am.getJWTGroupsChanges(user, groups, jwtGroupsNames)
		if err != nil {
			return fmt.Errorf("error getting JWT groups changes: %w", err)
		}

		hasChanges = changed
		// skip update if no changes
		if !changed {
			return nil
		}

		if err = transaction.SaveGroups(ctx, store.LockingStrengthUpdate, newGroupsToCreate); err != nil {
			return fmt.Errorf("error saving groups: %w", err)
		}

		addNewGroups = util.Difference(updatedAutoGroups, user.AutoGroups)
		removeOldGroups = util.Difference(user.AutoGroups, updatedAutoGroups)

		user.AutoGroups = updatedAutoGroups
		if err = transaction.SaveUser(ctx, store.LockingStrengthUpdate, user); err != nil {
			return fmt.Errorf("error saving user: %w", err)
		}

		// Propagate changes to peers if group propagation is enabled
		if settings.GroupsPropagationEnabled {
			groups, err = transaction.GetAccountGroups(ctx, store.LockingStrengthShare, accountID)
			if err != nil {
				return fmt.Errorf("error getting account groups: %w", err)
			}

			groupsMap := make(map[string]*types.Group, len(groups))
			for _, group := range groups {
				groupsMap[group.ID] = group
			}

			peers, err := transaction.GetUserPeers(ctx, store.LockingStrengthShare, accountID, claims.UserId)
			if err != nil {
				return fmt.Errorf("error getting user peers: %w", err)
			}

			updatedGroups, err := am.updateUserPeersInGroups(groupsMap, peers, addNewGroups, removeOldGroups)
			if err != nil {
				return fmt.Errorf("error modifying user peers in groups: %w", err)
			}

			if err = transaction.SaveGroups(ctx, store.LockingStrengthUpdate, updatedGroups); err != nil {
				return fmt.Errorf("error saving groups: %w", err)
			}

			if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
				return fmt.Errorf("error incrementing network serial: %w", err)
			}
		}
		unlockAccount()
		unlockAccount = nil

		return nil
	})
	if err != nil {
		return err
	}

	if !hasChanges {
		return nil
	}

	for _, g := range addNewGroups {
		group, err := am.Store.GetGroupByID(ctx, store.LockingStrengthShare, accountID, g)
		if err != nil {
			log.WithContext(ctx).Debugf("group %s not found while saving user activity event of account %s", g, accountID)
		} else {
			meta := map[string]any{
				"group": group.Name, "group_id": group.ID,
				"is_service_user": user.IsServiceUser, "user_name": user.ServiceUserName,
			}
			am.StoreEvent(ctx, user.Id, user.Id, accountID, activity.GroupAddedToUser, meta)
		}
	}

	for _, g := range removeOldGroups {
		group, err := am.Store.GetGroupByID(ctx, store.LockingStrengthShare, accountID, g)
		if err != nil {
			log.WithContext(ctx).Debugf("group %s not found while saving user activity event of account %s", g, accountID)
		} else {
			meta := map[string]any{
				"group": group.Name, "group_id": group.ID,
				"is_service_user": user.IsServiceUser, "user_name": user.ServiceUserName,
			}
			am.StoreEvent(ctx, user.Id, user.Id, accountID, activity.GroupRemovedFromUser, meta)
		}
	}

	if settings.GroupsPropagationEnabled {
		removedGroupAffectsPeers, err := areGroupChangesAffectPeers(ctx, am.Store, accountID, removeOldGroups)
		if err != nil {
			return err
		}

		newGroupsAffectsPeers, err := areGroupChangesAffectPeers(ctx, am.Store, accountID, addNewGroups)
		if err != nil {
			return err
		}

		if removedGroupAffectsPeers || newGroupsAffectsPeers {
			log.WithContext(ctx).Tracef("user %s: JWT group membership changed, updating account peers", claims.UserId)
			am.UpdateAccountPeers(ctx, accountID)
		}
	}

	return nil
}

// getAccountIDWithAuthorizationClaims retrieves an account ID using JWT Claims.
// if domain is not private or domain is invalid, it will return the account ID by user ID.
// if domain is of the PrivateCategory category, it will evaluate
// if account is new, existing or if there is another account with the same domain
//
// Use cases:
//
// New user + New account + New domain -> create account, user role = owner (if private domain, index domain)
//
// New user + New account + Existing Private Domain -> add user to the existing account, user role = user (not admin)
//
// New user + New account + Existing Public Domain -> create account, user role = owner
//
// Existing user + Existing account + Existing Domain -> Nothing changes (if private, index domain)
//
// Existing user + Existing account + Existing Indexed Domain -> Nothing changes
//
// Existing user + Existing account + Existing domain reclassified Domain as private -> Nothing changes (index domain)
func (am *DefaultAccountManager) getAccountIDWithAuthorizationClaims(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, error) {
	log.WithContext(ctx).Tracef("getting account with authorization claims. User ID: \"%s\", Account ID: \"%s\", Domain: \"%s\", Domain Category: \"%s\"",
		claims.UserId, claims.AccountId, claims.Domain, claims.DomainCategory)

	if claims.UserId == "" {
		return "", errors.New(emptyUserID)
	}

	if claims.DomainCategory != types.PrivateCategory || !isDomainValid(claims.Domain) {
		return am.GetAccountIDByUserID(ctx, claims.UserId, claims.Domain)
	}

	if claims.AccountId != "" {
		return am.handlePrivateAccountWithIDFromClaim(ctx, claims)
	}

	// We checked if the domain has a primary account already
	domainAccountID, cancel, err := am.getPrivateDomainWithGlobalLock(ctx, claims.Domain)
	if cancel != nil {
		defer cancel()
	}
	if err != nil {
		return "", err
	}

	userAccountID, err := am.Store.GetAccountIDByUserID(ctx, store.LockingStrengthShare, claims.UserId)
	if handleNotFound(err) != nil {
		log.WithContext(ctx).Errorf("error getting account ID by user ID: %v", err)
		return "", err
	}

	if userAccountID != "" {
		if err = am.handleExistingUserAccount(ctx, userAccountID, domainAccountID, claims); err != nil {
			return "", err
		}

		return userAccountID, nil
	}

	if domainAccountID != "" {
		return am.addNewUserToDomainAccount(ctx, domainAccountID, claims)
	}

	return am.addNewPrivateAccount(ctx, domainAccountID, claims)
}
func (am *DefaultAccountManager) getPrivateDomainWithGlobalLock(ctx context.Context, domain string) (string, context.CancelFunc, error) {
	domainAccountID, err := am.Store.GetAccountIDByPrivateDomain(ctx, store.LockingStrengthShare, domain)
	if handleNotFound(err) != nil {

		log.WithContext(ctx).Errorf(errorGettingDomainAccIDFmt, err)
		return "", nil, err
	}

	if domainAccountID != "" {
		return domainAccountID, nil, nil
	}

	log.WithContext(ctx).Debugf("no primary account found for domain %s, acquiring global lock", domain)
	cancel := am.Store.AcquireGlobalLock(ctx)

	// check again if the domain has a primary account because of simultaneous requests
	domainAccountID, err = am.Store.GetAccountIDByPrivateDomain(ctx, store.LockingStrengthShare, domain)
	if handleNotFound(err) != nil {
		cancel()
		log.WithContext(ctx).Errorf(errorGettingDomainAccIDFmt, err)
		return "", nil, err
	}

	return domainAccountID, cancel, nil
}

func (am *DefaultAccountManager) handlePrivateAccountWithIDFromClaim(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, error) {
	userAccountID, err := am.Store.GetAccountIDByUserID(ctx, store.LockingStrengthShare, claims.UserId)
	if err != nil {
		log.WithContext(ctx).Errorf("error getting account ID by user ID: %v", err)
		return "", err
	}

	if userAccountID != claims.AccountId {
		return "", fmt.Errorf("user %s is not part of the account id %s", claims.UserId, claims.AccountId)
	}

	accountDomain, domainCategory, err := am.Store.GetAccountDomainAndCategory(ctx, store.LockingStrengthShare, claims.AccountId)
	if handleNotFound(err) != nil {
		log.WithContext(ctx).Errorf("error getting account domain and category: %v", err)
		return "", err
	}

	if domainIsUpToDate(accountDomain, domainCategory, claims) {
		return claims.AccountId, nil
	}

	// We checked if the domain has a primary account already
	domainAccountID, err := am.Store.GetAccountIDByPrivateDomain(ctx, store.LockingStrengthShare, claims.Domain)
	if handleNotFound(err) != nil {
		log.WithContext(ctx).Errorf(errorGettingDomainAccIDFmt, err)
		return "", err
	}

	err = am.handleExistingUserAccount(ctx, claims.AccountId, domainAccountID, claims)
	if err != nil {
		return "", err
	}

	return claims.AccountId, nil
}

func handleNotFound(err error) error {
	if err == nil {
		return nil
	}

	e, ok := status.FromError(err)
	if !ok || e.Type() != status.NotFound {
		return err
	}
	return nil
}

func domainIsUpToDate(domain string, domainCategory string, claims jwtclaims.AuthorizationClaims) bool {
	return domainCategory == types.PrivateCategory || claims.DomainCategory != types.PrivateCategory || domain != claims.Domain
}

func (am *DefaultAccountManager) SyncAndMarkPeer(ctx context.Context, accountID string, peerPubKey string, meta nbpeer.PeerSystemMeta, realIP net.IP) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error) {
	start := time.Now()
	defer func() {
		log.WithContext(ctx).Debugf("SyncAndMarkPeer: took %v", time.Since(start))
	}()

	accountUnlock := am.Store.AcquireReadLockByUID(ctx, accountID)
	defer accountUnlock()
	peerUnlock := am.Store.AcquireWriteLockByUID(ctx, peerPubKey)
	defer peerUnlock()

	peer, netMap, postureChecks, err := am.SyncPeer(ctx, PeerSync{WireGuardPubKey: peerPubKey, Meta: meta}, accountID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error syncing peer: %w", err)
	}

	err = am.MarkPeerConnected(ctx, peerPubKey, true, realIP, accountID)
	if err != nil {
		log.WithContext(ctx).Warnf("failed marking peer as connected %s %v", peerPubKey, err)
	}

	return peer, netMap, postureChecks, nil
}

func (am *DefaultAccountManager) OnPeerDisconnected(ctx context.Context, accountID string, peerPubKey string) error {
	accountUnlock := am.Store.AcquireReadLockByUID(ctx, accountID)
	defer accountUnlock()
	peerUnlock := am.Store.AcquireWriteLockByUID(ctx, peerPubKey)
	defer peerUnlock()

	err := am.MarkPeerConnected(ctx, peerPubKey, false, nil, accountID)
	if err != nil {
		log.WithContext(ctx).Warnf("failed marking peer as disconnected %s %v", peerPubKey, err)
	}

	return nil

}

func (am *DefaultAccountManager) SyncPeerMeta(ctx context.Context, peerPubKey string, meta nbpeer.PeerSystemMeta) error {
	accountID, err := am.Store.GetAccountIDByPeerPubKey(ctx, peerPubKey)
	if err != nil {
		return err
	}

	unlock := am.Store.AcquireReadLockByUID(ctx, accountID)
	defer unlock()

	unlockPeer := am.Store.AcquireWriteLockByUID(ctx, peerPubKey)
	defer unlockPeer()

	_, _, _, err = am.SyncPeer(ctx, PeerSync{WireGuardPubKey: peerPubKey, Meta: meta, UpdateAccountPeers: true}, accountID)
	if err != nil {
		return mapError(ctx, err)
	}
	return nil
}

// GetAllConnectedPeers returns connected peers based on peersUpdateManager.GetAllConnectedPeers()
func (am *DefaultAccountManager) GetAllConnectedPeers() (map[string]struct{}, error) {
	return am.peersUpdateManager.GetAllConnectedPeers(), nil
}

// HasConnectedChannel returns true if peers has channel in update manager, otherwise false
func (am *DefaultAccountManager) HasConnectedChannel(peerID string) bool {
	return am.peersUpdateManager.HasChannel(peerID)
}

var invalidDomainRegexp = regexp.MustCompile(`^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$`)

func isDomainValid(domain string) bool {
	return invalidDomainRegexp.MatchString(domain)
}

// GetDNSDomain returns the configured dnsDomain
func (am *DefaultAccountManager) GetDNSDomain() string {
	return am.dnsDomain
}

// CheckUserAccessByJWTGroups checks if the user has access, particularly in cases where the admin enabled JWT
// group propagation and set the list of groups with access permissions.
func (am *DefaultAccountManager) CheckUserAccessByJWTGroups(ctx context.Context, claims jwtclaims.AuthorizationClaims) error {
	accountID, _, err := am.GetAccountIDFromToken(ctx, claims)
	if err != nil {
		return err
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return err
	}

	// Ensures JWT group synchronization to the management is enabled before,
	// filtering access based on the allowed groups.
	if settings != nil && settings.JWTGroupsEnabled {
		if allowedGroups := settings.JWTAllowGroups; len(allowedGroups) > 0 {
			userJWTGroups := extractJWTGroups(ctx, settings.JWTGroupsClaimName, claims)

			if !userHasAllowedGroup(allowedGroups, userJWTGroups) {
				return fmt.Errorf("user does not belong to any of the allowed JWT groups")
			}
		}
	}

	return nil
}

func (am *DefaultAccountManager) onPeersInvalidated(ctx context.Context, accountID string) {
	log.WithContext(ctx).Debugf("validated peers has been invalidated for account %s", accountID)
	am.UpdateAccountPeers(ctx, accountID)
}

func (am *DefaultAccountManager) FindExistingPostureCheck(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error) {
	return am.Store.GetPostureCheckByChecksDefinition(accountID, checks)
}

func (am *DefaultAccountManager) GetAccountIDForPeerKey(ctx context.Context, peerKey string) (string, error) {
	return am.Store.GetAccountIDByPeerPubKey(ctx, peerKey)
}

func (am *DefaultAccountManager) handleUserPeer(ctx context.Context, transaction store.Store, peer *nbpeer.Peer, settings *types.Settings) (bool, error) {
	user, err := transaction.GetUserByUserID(ctx, store.LockingStrengthShare, peer.UserID)
	if err != nil {
		return false, err
	}

	err = checkIfPeerOwnerIsBlocked(peer, user)
	if err != nil {
		return false, err
	}

	if peerLoginExpired(ctx, peer, settings) {
		err = am.handleExpiredPeer(ctx, transaction, user, peer)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	return false, nil
}

func (am *DefaultAccountManager) getFreeDNSLabel(ctx context.Context, s store.Store, accountID string, peerHostName string) (string, error) {
	existingLabels, err := s.GetPeerLabelsInAccount(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return "", fmt.Errorf("failed to get peer dns labels: %w", err)
	}

	labelMap := ConvertSliceToMap(existingLabels)
	newLabel, err := types.GetPeerHostLabel(peerHostName, labelMap)
	if err != nil {
		return "", fmt.Errorf("failed to get new host label: %w", err)
	}

	if newLabel == "" {
		return "", fmt.Errorf("failed to get new host label: %w", err)
	}

	return newLabel, nil
}

func (am *DefaultAccountManager) GetAccountSettings(ctx context.Context, accountID string, userID string) (*types.Settings, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID || (!user.HasAdminPower() && !user.IsServiceUser) {
		return nil, status.Errorf(status.PermissionDenied, "the user has no permission to access account data")
	}

	return am.Store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
}

// addAllGroup to account object if it doesn't exist
func addAllGroup(account *types.Account) error {
	if len(account.Groups) == 0 {
		allGroup := &types.Group{
			ID:     xid.New().String(),
			Name:   "All",
			Issued: types.GroupIssuedAPI,
		}
		for _, peer := range account.Peers {
			allGroup.Peers = append(allGroup.Peers, peer.ID)
		}
		account.Groups = map[string]*types.Group{allGroup.ID: allGroup}

		id := xid.New().String()

		defaultPolicy := &types.Policy{
			ID:          id,
			Name:        types.DefaultRuleName,
			Description: types.DefaultRuleDescription,
			Enabled:     true,
			Rules: []*types.PolicyRule{
				{
					ID:            id,
					Name:          types.DefaultRuleName,
					Description:   types.DefaultRuleDescription,
					Enabled:       true,
					Sources:       []string{allGroup.ID},
					Destinations:  []string{allGroup.ID},
					Bidirectional: true,
					Protocol:      types.PolicyRuleProtocolALL,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}

		account.Policies = []*types.Policy{defaultPolicy}
	}
	return nil
}

// newAccountWithId creates a new Account with a default SetupKey (doesn't store in a Store) and provided id
func newAccountWithId(ctx context.Context, accountID, userID, domain string) *types.Account {
	log.WithContext(ctx).Debugf("creating new account")

	network := types.NewNetwork()
	peers := make(map[string]*nbpeer.Peer)
	users := make(map[string]*types.User)
	routes := make(map[route.ID]*route.Route)
	setupKeys := map[string]*types.SetupKey{}
	nameServersGroups := make(map[string]*nbdns.NameServerGroup)

	owner := types.NewOwnerUser(userID)
	owner.AccountID = accountID
	users[userID] = owner

	dnsSettings := types.DNSSettings{
		DisabledManagementGroups: make([]string, 0),
	}
	log.WithContext(ctx).Debugf("created new account %s", accountID)

	acc := &types.Account{
		Id:               accountID,
		CreatedAt:        time.Now().UTC(),
		SetupKeys:        setupKeys,
		Network:          network,
		Peers:            peers,
		Users:            users,
		CreatedBy:        userID,
		Domain:           domain,
		Routes:           routes,
		NameServerGroups: nameServersGroups,
		DNSSettings:      dnsSettings,
		Settings: &types.Settings{
			PeerLoginExpirationEnabled: true,
			PeerLoginExpiration:        types.DefaultPeerLoginExpiration,
			GroupsPropagationEnabled:   true,
			RegularUsersViewBlocked:    true,

			PeerInactivityExpirationEnabled: false,
			PeerInactivityExpiration:        types.DefaultPeerInactivityExpiration,
			RoutingPeerDNSResolutionEnabled: true,
		},
	}

	if err := addAllGroup(acc); err != nil {
		log.WithContext(ctx).Errorf("error adding all group to account %s: %v", acc.Id, err)
	}
	return acc
}

// extractJWTGroups extracts the group names from a JWT token's claims.
func extractJWTGroups(ctx context.Context, claimName string, claims jwtclaims.AuthorizationClaims) []string {
	userJWTGroups := make([]string, 0)

	if claim, ok := claims.Raw[claimName]; ok {
		if claimGroups, ok := claim.([]interface{}); ok {
			for _, g := range claimGroups {
				if group, ok := g.(string); ok {
					userJWTGroups = append(userJWTGroups, group)
				} else {
					log.WithContext(ctx).Debugf("JWT claim %q contains a non-string group (type: %T): %v", claimName, g, g)
				}
			}
		}
	} else {
		log.WithContext(ctx).Debugf("JWT claim %q is not a string array", claimName)
	}

	return userJWTGroups
}

// userHasAllowedGroup checks if a user belongs to any of the allowed groups.
func userHasAllowedGroup(allowedGroups []string, userGroups []string) bool {
	for _, userGroup := range userGroups {
		for _, allowedGroup := range allowedGroups {
			if userGroup == allowedGroup {
				return true
			}
		}
	}
	return false
}

// separateGroups separates user's auto groups into non-JWT and JWT groups.
// Returns the list of standard auto groups and a map of JWT auto groups,
// where the keys are the group names and the values are the group IDs.
func separateGroups(autoGroups []string, allGroups []*types.Group) ([]string, map[string]string) {
	newAutoGroups := make([]string, 0)
	jwtAutoGroups := make(map[string]string) // map of group name to group ID

	allGroupsMap := make(map[string]*types.Group, len(allGroups))
	for _, group := range allGroups {
		allGroupsMap[group.ID] = group
	}

	for _, id := range autoGroups {
		if group, ok := allGroupsMap[id]; ok {
			if group.Issued == types.GroupIssuedJWT {
				jwtAutoGroups[group.Name] = id
			} else {
				newAutoGroups = append(newAutoGroups, id)
			}
		}
	}

	return newAutoGroups, jwtAutoGroups
}
