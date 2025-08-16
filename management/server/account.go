package server

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cacheStore "github.com/eko/gocache/lib/v4/store"
	"github.com/eko/gocache/store/redis/v4"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/formatter/hook"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	peerSchedulerRetryInterval = 3 * time.Second
	emptyUserID                = "empty user ID in claims"
	errorGettingDomainAccIDFmt = "error getting account ID by private domain: %v"
)

type userLoggedInOnce bool

func cacheEntryExpiration() time.Duration {
	r := rand.Intn(int(nbcache.DefaultIDPCacheExpirationMax.Milliseconds()-nbcache.DefaultIDPCacheExpirationMin.Milliseconds())) + int(nbcache.DefaultIDPCacheExpirationMin.Milliseconds())
	return time.Duration(r) * time.Millisecond
}

type DefaultAccountManager struct {
	Store store.Store
	// cacheMux and cacheLoading helps to make sure that only a single cache reload runs at a time per accountID
	cacheMux sync.Mutex
	// cacheLoading keeps the accountIDs that are currently reloading. The accountID has to be removed once cache has been reloaded
	cacheLoading         map[string]chan struct{}
	peersUpdateManager   *PeersUpdateManager
	peersJobManager      *PeersJobManager
	idpManager           idp.Manager
	cacheManager         *nbcache.AccountUserDataCache
	externalCacheManager nbcache.UserDataCache
	ctx                  context.Context
	eventStore           activity.Store
	geo                  geolocation.Geolocation

	requestBuffer *AccountRequestBuffer

	proxyController port_forwarding.Controller
	settingsManager settings.Manager

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

	permissionsManager permissions.Manager

	accountUpdateLocks               sync.Map
	updateAccountPeersBufferInterval atomic.Int64

	disableDefaultPolicy bool
}

func isUniqueConstraintError(err error) bool {
	switch {
	case strings.Contains(err.Error(), "(SQLSTATE 23505)"),
		strings.Contains(err.Error(), "Error 1062 (23000)"),
		strings.Contains(err.Error(), "UNIQUE constraint failed"):
		return true

	default:
		return false
	}
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
	peersJobManager *PeersJobManager,
	idpManager idp.Manager,
	singleAccountModeDomain string,
	dnsDomain string,
	eventStore activity.Store,
	geo geolocation.Geolocation,
	userDeleteFromIDPEnabled bool,
	integratedPeerValidator integrated_validator.IntegratedValidator,
	metrics telemetry.AppMetrics,
	proxyController port_forwarding.Controller,
	settingsManager settings.Manager,
	permissionsManager permissions.Manager,
	disableDefaultPolicy bool,
) (*DefaultAccountManager, error) {
	start := time.Now()
	defer func() {
		log.WithContext(ctx).Debugf("took %v to instantiate account manager", time.Since(start))
	}()

	am := &DefaultAccountManager{
		Store:                    store,
		geo:                      geo,
		peersUpdateManager:       peersUpdateManager,
		peersJobManager:          peersJobManager,
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
		proxyController:          proxyController,
		settingsManager:          settingsManager,
		permissionsManager:       permissionsManager,
		disableDefaultPolicy:     disableDefaultPolicy,
	}

	am.startWarmup(ctx)

	accountsCounter, err := store.GetAccountsCounter(ctx)
	if err != nil {
		log.WithContext(ctx).Error(err)
	}

	// enable single account mode only if configured by user and number of existing accounts is not grater than 1
	am.singleAccountMode = singleAccountModeDomain != "" && accountsCounter <= 1
	if am.singleAccountMode {
		if !isDomainValid(singleAccountModeDomain) {
			return nil, status.Errorf(status.InvalidArgument, "invalid domain \"%s\" provided for a single account mode. Please review your input for --single-account-mode-domain", singleAccountModeDomain)
		}
		am.singleAccountModeDomain = singleAccountModeDomain
		log.WithContext(ctx).Infof("single account mode enabled, accounts number %d", accountsCounter)
	} else {
		log.WithContext(ctx).Infof("single account mode disabled, accounts number %d", accountsCounter)
	}

	cacheStore, err := nbcache.NewStore(ctx, nbcache.DefaultIDPCacheExpirationMax, nbcache.DefaultIDPCacheCleanupInterval)
	if err != nil {
		return nil, fmt.Errorf("getting cache store: %s", err)
	}
	am.externalCacheManager = nbcache.NewUserDataCache(cacheStore)
	am.cacheManager = nbcache.NewAccountUserDataCache(am.loadAccount, cacheStore)

	if !isNil(am.idpManager) {
		go func() {
			err := am.warmupIDPCache(ctx, cacheStore)
			if err != nil {
				log.WithContext(ctx).Warnf("failed warming up cache due to error: %v", err)
				// todo retry?
				return
			}
		}()
	}

	am.integratedPeerValidator.SetPeerInvalidationListener(func(accountID string, peerIDs []string) {
		am.onPeersInvalidated(ctx, accountID, peerIDs)
	})

	return am, nil
}

func (am *DefaultAccountManager) startWarmup(ctx context.Context) {
	var initialInterval int64
	intervalStr := os.Getenv("NB_PEER_UPDATE_INTERVAL_MS")
	interval, err := strconv.Atoi(intervalStr)
	if err != nil {
		initialInterval = 1
		log.WithContext(ctx).Warnf("failed to parse peer update interval, using default value %dms: %v", initialInterval, err)
	} else {
		initialInterval = int64(interval) * 10
		go func() {
			startupPeriodStr := os.Getenv("NB_PEER_UPDATE_STARTUP_PERIOD_S")
			startupPeriod, err := strconv.Atoi(startupPeriodStr)
			if err != nil {
				startupPeriod = 1
				log.WithContext(ctx).Warnf("failed to parse peer update startup period, using default value %ds: %v", startupPeriod, err)
			}
			time.Sleep(time.Duration(startupPeriod) * time.Second)
			am.updateAccountPeersBufferInterval.Store(int64(time.Duration(interval) * time.Millisecond))
			log.WithContext(ctx).Infof("set peer update buffer interval to %dms", interval)
		}()
	}
	am.updateAccountPeersBufferInterval.Store(initialInterval)
	log.WithContext(ctx).Infof("set peer update buffer interval to %dms", initialInterval)

}

func (am *DefaultAccountManager) GetExternalCacheManager() account.ExternalCacheManager {
	return am.externalCacheManager
}

func (am *DefaultAccountManager) GetIdpManager() idp.Manager {
	return am.idpManager
}

// UpdateAccountSettings updates Account settings.
// Only users with role UserRoleAdmin can update the account.
// User that performs the update has to belong to the account.
// Returns an updated Settings
func (am *DefaultAccountManager) UpdateAccountSettings(ctx context.Context, accountID, userID string, newSettings *types.Settings) (*types.Settings, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Update)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}

	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	var oldSettings *types.Settings
	var updateAccountPeers bool
	var groupChangesAffectPeers bool

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		var groupsUpdated bool

		oldSettings, err = transaction.GetAccountSettings(ctx, store.LockingStrengthUpdate, accountID)
		if err != nil {
			return err
		}

		if err = am.validateSettingsUpdate(ctx, transaction, newSettings, oldSettings, userID, accountID); err != nil {
			return err
		}

		if oldSettings.NetworkRange != newSettings.NetworkRange {
			if err = am.reallocateAccountPeerIPs(ctx, transaction, accountID, newSettings.NetworkRange); err != nil {
				return err
			}
			updateAccountPeers = true
		}

		if oldSettings.RoutingPeerDNSResolutionEnabled != newSettings.RoutingPeerDNSResolutionEnabled ||
			oldSettings.LazyConnectionEnabled != newSettings.LazyConnectionEnabled ||
			oldSettings.DNSDomain != newSettings.DNSDomain {
			updateAccountPeers = true
		}

		if oldSettings.GroupsPropagationEnabled != newSettings.GroupsPropagationEnabled && newSettings.GroupsPropagationEnabled {
			groupsUpdated, groupChangesAffectPeers, err = propagateUserGroupMemberships(ctx, transaction, accountID)
			if err != nil {
				return err
			}
		}

		if updateAccountPeers || groupsUpdated {
			if err = transaction.IncrementNetworkSerial(ctx, accountID); err != nil {
				return err
			}
		}

		return transaction.SaveAccountSettings(ctx, accountID, newSettings)
	})
	if err != nil {
		return nil, err
	}

	extraSettingsChanged, err := am.settingsManager.UpdateExtraSettings(ctx, accountID, userID, newSettings.Extra)
	if err != nil {
		return nil, err
	}

	am.handleRoutingPeerDNSResolutionSettings(ctx, oldSettings, newSettings, userID, accountID)
	am.handleLazyConnectionSettings(ctx, oldSettings, newSettings, userID, accountID)
	am.handlePeerLoginExpirationSettings(ctx, oldSettings, newSettings, userID, accountID)
	am.handleGroupsPropagationSettings(ctx, oldSettings, newSettings, userID, accountID)
	if err = am.handleInactivityExpirationSettings(ctx, oldSettings, newSettings, userID, accountID); err != nil {
		return nil, err
	}
	if oldSettings.DNSDomain != newSettings.DNSDomain {
		eventMeta := map[string]any{
			"old_dns_domain": oldSettings.DNSDomain,
			"new_dns_domain": newSettings.DNSDomain,
		}
		am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountDNSDomainUpdated, eventMeta)
	}
	if oldSettings.NetworkRange != newSettings.NetworkRange {
		eventMeta := map[string]any{
			"old_network_range": oldSettings.NetworkRange.String(),
			"new_network_range": newSettings.NetworkRange.String(),
		}
		am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountNetworkRangeUpdated, eventMeta)
	}

	if updateAccountPeers || extraSettingsChanged || groupChangesAffectPeers {
		go am.UpdateAccountPeers(ctx, accountID)
	}

	return newSettings, nil
}

func (am *DefaultAccountManager) validateSettingsUpdate(ctx context.Context, transaction store.Store, newSettings, oldSettings *types.Settings, userID, accountID string) error {
	halfYearLimit := 180 * 24 * time.Hour
	if newSettings.PeerLoginExpiration > halfYearLimit {
		return status.Errorf(status.InvalidArgument, "peer login expiration can't be larger than 180 days")
	}

	if newSettings.PeerLoginExpiration < time.Hour {
		return status.Errorf(status.InvalidArgument, "peer login expiration can't be smaller than one hour")
	}

	if newSettings.DNSDomain != "" && !isDomainValid(newSettings.DNSDomain) {
		return status.Errorf(status.InvalidArgument, "invalid domain \"%s\" provided for DNS domain", newSettings.DNSDomain)
	}

	peers, err := transaction.GetAccountPeers(ctx, store.LockingStrengthNone, accountID, "", "")
	if err != nil {
		return err
	}

	peersMap := make(map[string]*nbpeer.Peer, len(peers))
	for _, peer := range peers {
		peersMap[peer.ID] = peer
	}

	return am.integratedPeerValidator.ValidateExtraSettings(ctx, newSettings.Extra, oldSettings.Extra, peersMap, userID, accountID)
}

func (am *DefaultAccountManager) handleRoutingPeerDNSResolutionSettings(ctx context.Context, oldSettings, newSettings *types.Settings, userID, accountID string) {
	if oldSettings.RoutingPeerDNSResolutionEnabled != newSettings.RoutingPeerDNSResolutionEnabled {
		if newSettings.RoutingPeerDNSResolutionEnabled {
			am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountRoutingPeerDNSResolutionEnabled, nil)
		} else {
			am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountRoutingPeerDNSResolutionDisabled, nil)
		}
	}
}

func (am *DefaultAccountManager) handleLazyConnectionSettings(ctx context.Context, oldSettings, newSettings *types.Settings, userID, accountID string) {
	if oldSettings.LazyConnectionEnabled != newSettings.LazyConnectionEnabled {
		if newSettings.LazyConnectionEnabled {
			am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountLazyConnectionEnabled, nil)
		} else {
			am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountLazyConnectionDisabled, nil)
		}
	}
}

func (am *DefaultAccountManager) handlePeerLoginExpirationSettings(ctx context.Context, oldSettings, newSettings *types.Settings, userID, accountID string) {
	if oldSettings.PeerLoginExpirationEnabled != newSettings.PeerLoginExpirationEnabled {
		event := activity.AccountPeerLoginExpirationEnabled
		if !newSettings.PeerLoginExpirationEnabled {
			event = activity.AccountPeerLoginExpirationDisabled
			am.peerLoginExpiry.Cancel(ctx, []string{accountID})
		} else {
			am.schedulePeerLoginExpiration(ctx, accountID)
		}
		am.StoreEvent(ctx, userID, accountID, accountID, event, nil)
	}

	if oldSettings.PeerLoginExpiration != newSettings.PeerLoginExpiration {
		am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountPeerLoginExpirationDurationUpdated, nil)
		am.peerLoginExpiry.Cancel(ctx, []string{accountID})
		am.schedulePeerLoginExpiration(ctx, accountID)
	}
}

func (am *DefaultAccountManager) handleGroupsPropagationSettings(ctx context.Context, oldSettings, newSettings *types.Settings, userID, accountID string) {
	if oldSettings.GroupsPropagationEnabled != newSettings.GroupsPropagationEnabled {
		if newSettings.GroupsPropagationEnabled {
			am.StoreEvent(ctx, userID, accountID, accountID, activity.UserGroupPropagationEnabled, nil)
		} else {
			am.StoreEvent(ctx, userID, accountID, accountID, activity.UserGroupPropagationDisabled, nil)
		}
	}
}

func (am *DefaultAccountManager) handleInactivityExpirationSettings(ctx context.Context, oldSettings, newSettings *types.Settings, userID, accountID string) error {
	if newSettings.PeerInactivityExpirationEnabled {
		if oldSettings.PeerInactivityExpiration != newSettings.PeerInactivityExpiration {
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
		//nolint
		ctx := context.WithValue(ctx, nbcontext.AccountIDKey, accountID)
		//nolint
		ctx = context.WithValue(ctx, hook.ExecutionContextKey, fmt.Sprintf("%s-PEER-EXPIRATION", hook.SystemSource))
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

func (am *DefaultAccountManager) schedulePeerLoginExpiration(ctx context.Context, accountID string) {
	if am.peerLoginExpiry.IsSchedulerRunning(accountID) {
		log.WithContext(ctx).Tracef("peer login expiration job for account %s is already scheduled", accountID)
		return
	}
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
			newAccount := newAccountWithId(ctx, accountId, userID, domain, am.disableDefaultPolicy)
			am.StoreEvent(ctx, userID, newAccount.Id, accountId, activity.AccountCreated, nil)
			return newAccount, nil
		default:
			return nil, err
		}
	}

	return nil, status.Errorf(status.Internal, "error while creating new account")
}

func (am *DefaultAccountManager) warmupIDPCache(ctx context.Context, store cacheStore.StoreInterface) error {
	cold, err := am.isCacheCold(ctx, store)
	if err != nil {
		return err
	}

	if !cold {
		log.WithContext(ctx).Debug("cache already populated, skipping warm up")
		return nil
	}

	if delayStr, ok := os.LookupEnv("NB_IDP_CACHE_WARMUP_DELAY"); ok {
		delay, err := time.ParseDuration(delayStr)
		if err != nil {
			return fmt.Errorf("invalid IDP warmup delay: %w", err)
		}
		time.Sleep(delay)
	}

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
		err = am.cacheManager.Set(am.ctx, accountID, users, cacheEntryExpiration())
		if err != nil {
			return err
		}
	}
	log.WithContext(ctx).Infof("warmed up IDP cache with %d entries for %d accounts", rcvdUsers, len(userData))
	return nil
}

// isCacheCold checks if the cache needs warming up.
func (am *DefaultAccountManager) isCacheCold(ctx context.Context, store cacheStore.StoreInterface) (bool, error) {
	if store.GetType() != redis.RedisType {
		return true, nil
	}

	accountID, err := am.Store.GetAnyAccountID(ctx)
	if err != nil {
		if sErr, ok := status.FromError(err); ok && sErr.Type() == status.NotFound {
			return true, nil
		}
		return false, err
	}

	_, err = store.Get(ctx, accountID)
	if err == nil {
		return false, nil
	}

	if notFoundErr := new(cacheStore.NotFound); errors.As(err, &notFoundErr) {
		return true, nil
	}

	return false, fmt.Errorf("failed to check cache: %w", err)
}

// DeleteAccount deletes an account and all its users from local store and from the remote IDP if the requester is an admin and account owner
func (am *DefaultAccountManager) DeleteAccount(ctx context.Context, accountID, userID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()
	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Accounts, operations.Delete)
	if err != nil {
		return fmt.Errorf("failed to validate user permissions: %w", err)
	}

	if !allowed {
		return status.Errorf(status.PermissionDenied, "user is not allowed to delete account. Only account owner can delete account")
	}

	userInfosMap, err := am.BuildUserInfosForAccount(ctx, accountID, userID, maps.Values(account.Users))
	if err != nil {
		return status.Errorf(status.Internal, "failed to build user infos for account %s: %v", accountID, err)
	}

	for _, otherUser := range account.Users {
		if otherUser.Id == userID {
			continue
		}

		if otherUser.IsServiceUser {
			err = am.deleteServiceUser(ctx, accountID, userID, otherUser)
			if err != nil {
				return err
			}
			continue
		}

		userInfo, ok := userInfosMap[otherUser.Id]
		if !ok {
			return status.Errorf(status.NotFound, "user info not found for user %s", otherUser.Id)
		}

		_, deleteUserErr := am.deleteRegularUser(ctx, accountID, userID, userInfo)
		if deleteUserErr != nil {
			return deleteUserErr
		}
	}

	userInfo, ok := userInfosMap[userID]
	if ok {
		_, err = am.deleteRegularUser(ctx, accountID, userID, userInfo)
		if err != nil {
			log.WithContext(ctx).Errorf("failed deleting user %s. error: %s", userID, err)
			return err
		}
	}

	err = am.Store.DeleteAccount(ctx, account)
	if err != nil {
		log.WithContext(ctx).Errorf("failed deleting account %s. error: %s", accountID, err)
		return err
	}
	// cancel peer login expiry job
	am.peerLoginExpiry.Cancel(ctx, []string{account.Id})

	meta := map[string]any{"account_id": account.Id, "domain": account.Domain, "created_at": account.CreatedAt}
	am.StoreEvent(ctx, userID, accountID, accountID, activity.AccountDeleted, meta)

	log.WithContext(ctx).Debugf("account %s deleted", accountID)
	return nil
}

// AccountExists checks if an account exists.
func (am *DefaultAccountManager) AccountExists(ctx context.Context, accountID string) (bool, error) {
	return am.Store.AccountExists(ctx, store.LockingStrengthNone, accountID)
}

// GetAccountIDByUserID retrieves the account ID based on the userID provided.
// If user does have an account, it returns the user's account ID.
// If the user doesn't have an account, it creates one using the provided domain.
// Returns the account ID or an error if none is found or created.
func (am *DefaultAccountManager) GetAccountIDByUserID(ctx context.Context, userID, domain string) (string, error) {
	if userID == "" {
		return "", status.Errorf(status.NotFound, "no valid userID provided")
	}

	accountID, err := am.Store.GetAccountIDByUserID(ctx, store.LockingStrengthNone, userID)
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
		// user can be nil if it wasn't found (e.g., just created)
		user, err := am.lookupUserInCache(ctx, userID, accountID)
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

func (am *DefaultAccountManager) loadAccount(ctx context.Context, accountID any) (any, []cacheStore.Option, error) {
	log.WithContext(ctx).Debugf("account %s not found in cache, reloading", accountID)
	accountIDString := fmt.Sprintf("%v", accountID)

	accountUsers, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountIDString)
	if err != nil {
		return nil, nil, err
	}

	userData, err := am.idpManager.GetAccount(ctx, accountIDString)
	if err != nil {
		return nil, nil, err
	}
	log.WithContext(ctx).Debugf("%d entries received from IdP management for account %s", len(userData), accountIDString)

	dataMap := make(map[string]*idp.UserData, len(userData))
	for _, datum := range userData {
		dataMap[datum.ID] = datum
	}

	matchedUserData := make([]*idp.UserData, 0)
	for _, user := range accountUsers {
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

	data, err := msgpack.Marshal(matchedUserData)
	if err != nil {
		return nil, nil, err
	}

	return data, []cacheStore.Option{cacheStore.WithExpiration(cacheEntryExpiration())}, nil
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
func (am *DefaultAccountManager) lookupUserInCache(ctx context.Context, userID string, accountID string) (*idp.UserData, error) {
	accountUsers, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	users := make(map[string]userLoggedInOnce, len(accountUsers))
	// ignore service users and users provisioned by integrations than are never logged in
	for _, user := range accountUsers {
		if user.IsServiceUser {
			continue
		}
		if user.Issued == types.UserIssuedIntegration {
			continue
		}
		users[user.Id] = userLoggedInOnce(!user.GetLastLogin().IsZero())
	}
	log.WithContext(ctx).Debugf("looking up user %s of account %s in cache", userID, accountID)
	userData, err := am.lookupCache(ctx, users, accountID)
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
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed finding user %s in account %s", userID, accountID)
		return nil, err
	}

	key := user.IntegrationReference.CacheKey(accountID, userID)
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

	return am.cacheManager.Set(am.ctx, accountID, data, cacheEntryExpiration())
}

// updateAccountDomainAttributesIfNotUpToDate updates the account domain attributes if they are not up to date and then, saves the account changes
func (am *DefaultAccountManager) updateAccountDomainAttributesIfNotUpToDate(ctx context.Context, accountID string, userAuth nbcontext.UserAuth,
	primaryDomain bool,
) error {
	if userAuth.Domain == "" {
		log.WithContext(ctx).Errorf("claims don't contain a valid domain, skipping domain attributes update. Received claims: %v", userAuth)
		return nil
	}

	unlockAccount := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlockAccount()

	accountDomain, domainCategory, err := am.Store.GetAccountDomainAndCategory(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error getting account domain and category: %v", err)
		return err
	}

	if domainIsUpToDate(accountDomain, domainCategory, userAuth) {
		return nil
	}

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userAuth.UserId)
	if err != nil {
		log.WithContext(ctx).Errorf("error getting user: %v", err)
		return err
	}

	newDomain := accountDomain
	newCategoty := domainCategory

	lowerDomain := strings.ToLower(userAuth.Domain)
	if accountDomain != lowerDomain && user.HasAdminPower() {
		newDomain = lowerDomain
	}

	if accountDomain == lowerDomain {
		newCategoty = userAuth.DomainCategory
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
	userAuth nbcontext.UserAuth,
) error {
	primaryDomain := domainAccountID == "" || userAccountID == domainAccountID
	err := am.updateAccountDomainAttributesIfNotUpToDate(ctx, userAccountID, userAuth, primaryDomain)
	if err != nil {
		return err
	}

	// we should register the account ID to this user's metadata in our IDP manager
	err = am.addAccountIDToIDPAppMeta(ctx, userAuth.UserId, userAccountID)
	if err != nil {
		return err
	}

	return nil
}

// addNewPrivateAccount validates if there is an existing primary account for the domain, if so it adds the new user to that account,
// otherwise it will create a new account and make it primary account for the domain.
func (am *DefaultAccountManager) addNewPrivateAccount(ctx context.Context, domainAccountID string, userAuth nbcontext.UserAuth) (string, error) {
	if userAuth.UserId == "" {
		return "", fmt.Errorf("user ID is empty")
	}

	lowerDomain := strings.ToLower(userAuth.Domain)

	newAccount, err := am.newAccount(ctx, userAuth.UserId, lowerDomain)
	if err != nil {
		return "", err
	}

	newAccount.Domain = lowerDomain
	newAccount.DomainCategory = userAuth.DomainCategory
	newAccount.IsDomainPrimaryAccount = true

	err = am.Store.SaveAccount(ctx, newAccount)
	if err != nil {
		return "", err
	}

	err = am.addAccountIDToIDPAppMeta(ctx, userAuth.UserId, newAccount.Id)
	if err != nil {
		return "", err
	}

	am.StoreEvent(ctx, userAuth.UserId, userAuth.UserId, newAccount.Id, activity.UserJoined, nil)

	return newAccount.Id, nil
}

func (am *DefaultAccountManager) addNewUserToDomainAccount(ctx context.Context, domainAccountID string, userAuth nbcontext.UserAuth) (string, error) {
	unlockAccount := am.Store.AcquireWriteLockByUID(ctx, domainAccountID)
	defer unlockAccount()

	newUser := types.NewRegularUser(userAuth.UserId)
	newUser.AccountID = domainAccountID
	err := am.Store.SaveUser(ctx, newUser)
	if err != nil {
		return "", err
	}

	err = am.addAccountIDToIDPAppMeta(ctx, userAuth.UserId, domainAccountID)
	if err != nil {
		return "", err
	}

	am.StoreEvent(ctx, userAuth.UserId, userAuth.UserId, domainAccountID, activity.UserJoined, nil)

	return domainAccountID, nil
}

// redeemInvite checks whether user has been invited and redeems the invite
func (am *DefaultAccountManager) redeemInvite(ctx context.Context, accountID string, userID string) error {
	// only possible with the enabled IdP manager
	if am.idpManager == nil {
		log.WithContext(ctx).Warnf("invites only work with enabled IdP manager")
		return nil
	}

	user, err := am.lookupUserInCache(ctx, userID, accountID)
	if err != nil {
		return err
	}

	if user == nil {
		return status.Errorf(status.NotFound, "user %s not found in the IdP", userID)
	}

	if user.AppMetadata.WTPendingInvite != nil && *user.AppMetadata.WTPendingInvite {
		log.WithContext(ctx).Infof("redeeming invite for user %s account %s", userID, accountID)
		// User has already logged in, meaning that IdP should have set wt_pending_invite to false.
		// Our job is to just reload cache.
		go func() {
			_, err = am.refreshCache(ctx, accountID)
			if err != nil {
				log.WithContext(ctx).Warnf("failed reloading cache when redeeming user %s under account %s", userID, accountID)
				return
			}
			log.WithContext(ctx).Debugf("user %s of account %s redeemed invite", user.ID, accountID)
			am.StoreEvent(ctx, userID, userID, accountID, activity.UserJoined, nil)
		}()
	}

	return nil
}

// GetAccount returns an account associated with this account ID.
func (am *DefaultAccountManager) GetAccount(ctx context.Context, accountID string) (*types.Account, error) {
	return am.Store.GetAccount(ctx, accountID)
}

// GetAccountByID returns an account associated with this account ID.
func (am *DefaultAccountManager) GetAccountByID(ctx context.Context, accountID string, userID string) (*types.Account, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Accounts, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetAccount(ctx, accountID)
}

// GetAccountMeta returns the account metadata associated with this account ID.
func (am *DefaultAccountManager) GetAccountMeta(ctx context.Context, accountID string, userID string) (*types.AccountMeta, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Accounts, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetAccountMeta(ctx, store.LockingStrengthNone, accountID)
}

// GetAccountOnboarding retrieves the onboarding information for a specific account.
func (am *DefaultAccountManager) GetAccountOnboarding(ctx context.Context, accountID string, userID string) (*types.AccountOnboarding, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Accounts, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}

	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	onboarding, err := am.Store.GetAccountOnboarding(ctx, accountID)
	if err != nil && err.Error() != status.NewAccountOnboardingNotFoundError(accountID).Error() {
		log.Errorf("failed to get account onboarding for accountssssssss %s: %v", accountID, err)
		return nil, err
	}

	if onboarding == nil {
		onboarding = &types.AccountOnboarding{
			AccountID: accountID,
		}
	}

	return onboarding, nil
}

func (am *DefaultAccountManager) UpdateAccountOnboarding(ctx context.Context, accountID, userID string, newOnboarding *types.AccountOnboarding) (*types.AccountOnboarding, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Update)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}

	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	oldOnboarding, err := am.Store.GetAccountOnboarding(ctx, accountID)
	if err != nil && err.Error() != status.NewAccountOnboardingNotFoundError(accountID).Error() {
		return nil, fmt.Errorf("failed to get account onboarding: %w", err)
	}

	if oldOnboarding == nil {
		oldOnboarding = &types.AccountOnboarding{
			AccountID: accountID,
		}
	}

	if newOnboarding == nil {
		return oldOnboarding, nil
	}

	if oldOnboarding.IsEqual(*newOnboarding) {
		log.WithContext(ctx).Debugf("no changes in onboarding for account %s", accountID)
		return oldOnboarding, nil
	}

	newOnboarding.AccountID = accountID
	err = am.Store.SaveAccountOnboarding(ctx, newOnboarding)
	if err != nil {
		return nil, fmt.Errorf("failed to update account onboarding: %w", err)
	}

	return newOnboarding, nil
}

func (am *DefaultAccountManager) GetAccountIDFromUserAuth(ctx context.Context, userAuth nbcontext.UserAuth) (string, string, error) {
	if userAuth.UserId == "" {
		return "", "", errors.New(emptyUserID)
	}
	if am.singleAccountMode && am.singleAccountModeDomain != "" {
		// This section is mostly related to self-hosted installations.
		// We override incoming domain claims to group users under a single account.
		userAuth.Domain = am.singleAccountModeDomain
		userAuth.DomainCategory = types.PrivateCategory
		log.WithContext(ctx).Debugf("overriding JWT Domain and DomainCategory claims since single account mode is enabled")
	}

	accountID, err := am.getAccountIDWithAuthorizationClaims(ctx, userAuth)
	if err != nil {
		return "", "", err
	}

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userAuth.UserId)
	if err != nil {
		// this is not really possible because we got an account by user ID
		return "", "", status.Errorf(status.NotFound, "user %s not found", userAuth.UserId)
	}

	if userAuth.IsChild {
		return accountID, user.Id, nil
	}

	if err := am.permissionsManager.ValidateAccountAccess(ctx, accountID, user, false); err != nil {
		return "", "", err
	}

	if !user.IsServiceUser && userAuth.Invited {
		err = am.redeemInvite(ctx, accountID, user.Id)
		if err != nil {
			return "", "", err
		}
	}

	return accountID, user.Id, nil
}

// syncJWTGroups processes the JWT groups for a user, updates the account based on the groups,
// and propagates changes to peers if group propagation is enabled.
// requires userAuth to have been ValidateAndParseToken and EnsureUserAccessByJWTGroups by the AuthManager
func (am *DefaultAccountManager) SyncUserJWTGroups(ctx context.Context, userAuth nbcontext.UserAuth) error {
	if userAuth.IsChild || userAuth.IsPAT {
		return nil
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, userAuth.AccountId)
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

	unlockAccount := am.Store.AcquireWriteLockByUID(ctx, userAuth.AccountId)
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
		user, err = transaction.GetUserByUserID(ctx, store.LockingStrengthNone, userAuth.UserId)
		if err != nil {
			return fmt.Errorf("error getting user: %w", err)
		}

		groups, err := transaction.GetAccountGroups(ctx, store.LockingStrengthNone, userAuth.AccountId)
		if err != nil {
			return fmt.Errorf("error getting account groups: %w", err)
		}

		changed, updatedAutoGroups, newGroupsToCreate, err := am.getJWTGroupsChanges(user, groups, userAuth.Groups)
		if err != nil {
			return fmt.Errorf("error getting JWT groups changes: %w", err)
		}

		hasChanges = changed
		// skip update if no changes
		if !changed {
			return nil
		}

		if err = transaction.CreateGroups(ctx, userAuth.AccountId, newGroupsToCreate); err != nil {
			return fmt.Errorf("error saving groups: %w", err)
		}

		addNewGroups = util.Difference(updatedAutoGroups, user.AutoGroups)
		removeOldGroups = util.Difference(user.AutoGroups, updatedAutoGroups)

		user.AutoGroups = updatedAutoGroups
		if err = transaction.SaveUser(ctx, user); err != nil {
			return fmt.Errorf("error saving user: %w", err)
		}

		// Propagate changes to peers if group propagation is enabled
		if settings.GroupsPropagationEnabled {
			peers, err := transaction.GetUserPeers(ctx, store.LockingStrengthNone, userAuth.AccountId, userAuth.UserId)
			if err != nil {
				return fmt.Errorf("error getting user peers: %w", err)
			}

			for _, peer := range peers {
				for _, g := range addNewGroups {
					if err := transaction.AddPeerToGroup(ctx, userAuth.AccountId, peer.ID, g); err != nil {
						return fmt.Errorf("error adding peer %s to group %s: %w", peer.ID, g, err)
					}
				}
				for _, g := range removeOldGroups {
					if err := transaction.RemovePeerFromGroup(ctx, peer.ID, g); err != nil {
						return fmt.Errorf("error removing peer %s from group %s: %w", peer.ID, g, err)
					}
				}
			}

			if err = transaction.IncrementNetworkSerial(ctx, userAuth.AccountId); err != nil {
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
		group, err := am.Store.GetGroupByID(ctx, store.LockingStrengthNone, userAuth.AccountId, g)
		if err != nil {
			log.WithContext(ctx).Debugf("group %s not found while saving user activity event of account %s", g, userAuth.AccountId)
		} else {
			meta := map[string]any{
				"group": group.Name, "group_id": group.ID,
				"is_service_user": user.IsServiceUser, "user_name": user.ServiceUserName,
			}
			am.StoreEvent(ctx, user.Id, user.Id, userAuth.AccountId, activity.GroupAddedToUser, meta)
		}
	}

	for _, g := range removeOldGroups {
		group, err := am.Store.GetGroupByID(ctx, store.LockingStrengthNone, userAuth.AccountId, g)
		if err != nil {
			log.WithContext(ctx).Debugf("group %s not found while saving user activity event of account %s", g, userAuth.AccountId)
		} else {
			meta := map[string]any{
				"group": group.Name, "group_id": group.ID,
				"is_service_user": user.IsServiceUser, "user_name": user.ServiceUserName,
			}
			am.StoreEvent(ctx, user.Id, user.Id, userAuth.AccountId, activity.GroupRemovedFromUser, meta)
		}
	}

	if settings.GroupsPropagationEnabled {
		removedGroupAffectsPeers, err := areGroupChangesAffectPeers(ctx, am.Store, userAuth.AccountId, removeOldGroups)
		if err != nil {
			return err
		}

		newGroupsAffectsPeers, err := areGroupChangesAffectPeers(ctx, am.Store, userAuth.AccountId, addNewGroups)
		if err != nil {
			return err
		}

		if removedGroupAffectsPeers || newGroupsAffectsPeers {
			log.WithContext(ctx).Tracef("user %s: JWT group membership changed, updating account peers", userAuth.UserId)
			am.BufferUpdateAccountPeers(ctx, userAuth.AccountId)
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
//
// UserAuth IsChild -> checks that account exists
func (am *DefaultAccountManager) getAccountIDWithAuthorizationClaims(ctx context.Context, userAuth nbcontext.UserAuth) (string, error) {
	log.WithContext(ctx).Tracef("getting account with authorization claims. User ID: \"%s\", Account ID: \"%s\", Domain: \"%s\", Domain Category: \"%s\"",
		userAuth.UserId, userAuth.AccountId, userAuth.Domain, userAuth.DomainCategory)

	if userAuth.UserId == "" {
		return "", errors.New(emptyUserID)
	}

	if userAuth.IsChild {
		exists, err := am.Store.AccountExists(ctx, store.LockingStrengthNone, userAuth.AccountId)
		if err != nil || !exists {
			return "", err
		}
		return userAuth.AccountId, nil
	}

	if userAuth.DomainCategory != types.PrivateCategory || !isDomainValid(userAuth.Domain) {
		return am.GetAccountIDByUserID(ctx, userAuth.UserId, userAuth.Domain)
	}

	if userAuth.AccountId != "" {
		return am.handlePrivateAccountWithIDFromClaim(ctx, userAuth)
	}

	// We checked if the domain has a primary account already
	domainAccountID, cancel, err := am.getPrivateDomainWithGlobalLock(ctx, userAuth.Domain)
	if cancel != nil {
		defer cancel()
	}
	if err != nil {
		return "", err
	}

	userAccountID, err := am.Store.GetAccountIDByUserID(ctx, store.LockingStrengthNone, userAuth.UserId)
	if handleNotFound(err) != nil {
		log.WithContext(ctx).Errorf("error getting account ID by user ID: %v", err)
		return "", err
	}

	if userAccountID != "" {
		if err = am.handleExistingUserAccount(ctx, userAccountID, domainAccountID, userAuth); err != nil {
			return "", err
		}

		return userAccountID, nil
	}

	if domainAccountID != "" {
		return am.addNewUserToDomainAccount(ctx, domainAccountID, userAuth)
	}

	return am.addNewPrivateAccount(ctx, domainAccountID, userAuth)
}
func (am *DefaultAccountManager) getPrivateDomainWithGlobalLock(ctx context.Context, domain string) (string, context.CancelFunc, error) {
	domainAccountID, err := am.Store.GetAccountIDByPrivateDomain(ctx, store.LockingStrengthNone, domain)
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
	domainAccountID, err = am.Store.GetAccountIDByPrivateDomain(ctx, store.LockingStrengthNone, domain)
	if handleNotFound(err) != nil {
		cancel()
		log.WithContext(ctx).Errorf(errorGettingDomainAccIDFmt, err)
		return "", nil, err
	}

	return domainAccountID, cancel, nil
}

func (am *DefaultAccountManager) handlePrivateAccountWithIDFromClaim(ctx context.Context, userAuth nbcontext.UserAuth) (string, error) {
	userAccountID, err := am.Store.GetAccountIDByUserID(ctx, store.LockingStrengthNone, userAuth.UserId)
	if err != nil {
		log.WithContext(ctx).Errorf("error getting account ID by user ID: %v", err)
		return "", err
	}

	if userAccountID != userAuth.AccountId {
		return "", fmt.Errorf("user %s is not part of the account id %s", userAuth.UserId, userAuth.AccountId)
	}

	accountDomain, domainCategory, err := am.Store.GetAccountDomainAndCategory(ctx, store.LockingStrengthNone, userAuth.AccountId)
	if handleNotFound(err) != nil {
		log.WithContext(ctx).Errorf("error getting account domain and category: %v", err)
		return "", err
	}

	if domainIsUpToDate(accountDomain, domainCategory, userAuth) {
		return userAuth.AccountId, nil
	}

	// We checked if the domain has a primary account already
	domainAccountID, err := am.Store.GetAccountIDByPrivateDomain(ctx, store.LockingStrengthNone, userAuth.Domain)
	if handleNotFound(err) != nil {
		log.WithContext(ctx).Errorf(errorGettingDomainAccIDFmt, err)
		return "", err
	}

	err = am.handleExistingUserAccount(ctx, userAuth.AccountId, domainAccountID, userAuth)
	if err != nil {
		return "", err
	}

	return userAuth.AccountId, nil
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

func domainIsUpToDate(domain string, domainCategory string, userAuth nbcontext.UserAuth) bool {
	return domainCategory == types.PrivateCategory || userAuth.DomainCategory != types.PrivateCategory || domain != userAuth.Domain
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

	peer, netMap, postureChecks, err := am.SyncPeer(ctx, types.PeerSync{WireGuardPubKey: peerPubKey, Meta: meta}, accountID)
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

	_, _, _, err = am.SyncPeer(ctx, types.PeerSync{WireGuardPubKey: peerPubKey, Meta: meta, UpdateAccountPeers: true}, accountID)
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
func (am *DefaultAccountManager) GetDNSDomain(settings *types.Settings) string {
	if settings == nil {
		return am.dnsDomain
	}
	if settings.DNSDomain == "" {
		return am.dnsDomain
	}

	return settings.DNSDomain
}

func (am *DefaultAccountManager) onPeersInvalidated(ctx context.Context, accountID string, peerIDs []string) {
	peers := []*nbpeer.Peer{}
	log.WithContext(ctx).Debugf("invalidating peers %v for account %s", peerIDs, accountID)
	for _, peerID := range peerIDs {
		peer, err := am.GetPeer(ctx, accountID, peerID, activity.SystemInitiator)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to get invalidated peer %s for account %s: %v", peerID, accountID, err)
			continue
		}
		peers = append(peers, peer)
	}
	if len(peers) > 0 {
		err := am.expireAndUpdatePeers(ctx, accountID, peers)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to expire and update invalidated peers for account %s: %v", accountID, err)
			return
		}
	} else {
		log.WithContext(ctx).Debugf("running invalidation with no invalid peers")
	}
	log.WithContext(ctx).Debugf("invalidated peers have been expired for account %s", accountID)
}

func (am *DefaultAccountManager) FindExistingPostureCheck(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error) {
	return am.Store.GetPostureCheckByChecksDefinition(accountID, checks)
}

func (am *DefaultAccountManager) GetAccountIDForPeerKey(ctx context.Context, peerKey string) (string, error) {
	return am.Store.GetAccountIDByPeerPubKey(ctx, peerKey)
}

func (am *DefaultAccountManager) handleUserPeer(ctx context.Context, transaction store.Store, peer *nbpeer.Peer, settings *types.Settings) (bool, error) {
	user, err := transaction.GetUserByUserID(ctx, store.LockingStrengthNone, peer.UserID)
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

func (am *DefaultAccountManager) GetAccountSettings(ctx context.Context, accountID string, userID string) (*types.Settings, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}
	return am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
}

// newAccountWithId creates a new Account with a default SetupKey (doesn't store in a Store) and provided id
func newAccountWithId(ctx context.Context, accountID, userID, domain string, disableDefaultPolicy bool) *types.Account {
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
		Onboarding: types.AccountOnboarding{
			OnboardingFlowPending: true,
			SignupFormPending:     true,
		},
	}

	if err := acc.AddAllGroup(disableDefaultPolicy); err != nil {
		log.WithContext(ctx).Errorf("error adding all group to account %s: %v", acc.Id, err)
	}
	return acc
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

func (am *DefaultAccountManager) GetStore() store.Store {
	return am.Store
}

func (am *DefaultAccountManager) GetOrCreateAccountByPrivateDomain(ctx context.Context, initiatorId, domain string) (*types.Account, bool, error) {
	cancel := am.Store.AcquireGlobalLock(ctx)
	defer cancel()

	existingPrimaryAccountID, err := am.Store.GetAccountIDByPrivateDomain(ctx, store.LockingStrengthNone, domain)
	if handleNotFound(err) != nil {
		return nil, false, err
	}

	// a primary account already exists for this private domain
	if err == nil {
		existingAccount, err := am.Store.GetAccount(ctx, existingPrimaryAccountID)
		if err != nil {
			return nil, false, err
		}

		return existingAccount, false, nil
	}

	// create a new account for this private domain
	// retry twice for new ID clashes
	for range 2 {
		accountId := xid.New().String()

		exists, err := am.Store.AccountExists(ctx, store.LockingStrengthNone, accountId)
		if err != nil || exists {
			continue
		}

		network := types.NewNetwork()
		peers := make(map[string]*nbpeer.Peer)
		users := make(map[string]*types.User)
		routes := make(map[route.ID]*route.Route)
		setupKeys := map[string]*types.SetupKey{}
		nameServersGroups := make(map[string]*nbdns.NameServerGroup)

		dnsSettings := types.DNSSettings{
			DisabledManagementGroups: make([]string, 0),
		}

		newAccount := &types.Account{
			Id:        accountId,
			CreatedAt: time.Now().UTC(),
			SetupKeys: setupKeys,
			Network:   network,
			Peers:     peers,
			Users:     users,
			// @todo check if using the MSP owner id here is ok
			CreatedBy:              initiatorId,
			Domain:                 strings.ToLower(domain),
			DomainCategory:         types.PrivateCategory,
			IsDomainPrimaryAccount: false,
			Routes:                 routes,
			NameServerGroups:       nameServersGroups,
			DNSSettings:            dnsSettings,
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

		if err := newAccount.AddAllGroup(am.disableDefaultPolicy); err != nil {
			return nil, false, status.Errorf(status.Internal, "failed to add all group to new account by private domain")
		}

		if err := am.Store.SaveAccount(ctx, newAccount); err != nil {
			log.WithContext(ctx).WithFields(log.Fields{
				"accountId": newAccount.Id,
				"domain":    domain,
			}).Errorf("failed to create new account: %v", err)
			return nil, false, err
		}

		am.StoreEvent(ctx, initiatorId, newAccount.Id, accountId, activity.AccountCreated, nil)
		return newAccount, true, nil
	}

	return nil, false, status.Errorf(status.Internal, "failed to get or create new account by private domain")
}

func (am *DefaultAccountManager) UpdateToPrimaryAccount(ctx context.Context, accountId string) (*types.Account, error) {
	var account *types.Account
	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		var err error
		account, err = transaction.GetAccount(ctx, accountId)
		if err != nil {
			return err
		}

		if account.IsDomainPrimaryAccount {
			return nil
		}

		existingPrimaryAccountID, err := transaction.GetAccountIDByPrivateDomain(ctx, store.LockingStrengthNone, account.Domain)

		// error is not a not found error
		if handleNotFound(err) != nil {
			return err
		}

		// a primary account already exists for this private domain
		if err == nil {
			log.WithContext(ctx).WithFields(log.Fields{
				"accountId":         accountId,
				"existingAccountId": existingPrimaryAccountID,
			}).Errorf("cannot update account to primary, another account already exists as primary for the same domain")
			return status.Errorf(status.Internal, "cannot update account to primary")
		}

		account.IsDomainPrimaryAccount = true

		if err := transaction.SaveAccount(ctx, account); err != nil {
			log.WithContext(ctx).WithFields(log.Fields{
				"accountId": accountId,
			}).Errorf("failed to update account to primary: %v", err)
			return status.Errorf(status.Internal, "failed to update account to primary")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return account, nil
}

// propagateUserGroupMemberships propagates all account users' group memberships to their peers.
// Returns true if any groups were modified, true if those updates affect peers and an error.
func propagateUserGroupMemberships(ctx context.Context, transaction store.Store, accountID string) (groupsUpdated bool, peersAffected bool, err error) {
	users, err := transaction.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return false, false, err
	}

	accountGroupPeers, err := transaction.GetAccountGroupPeers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return false, false, fmt.Errorf("error getting account group peers: %w", err)
	}

	accountGroups, err := transaction.GetAccountGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return false, false, fmt.Errorf("error getting account groups: %w", err)
	}

	for _, group := range accountGroups {
		if _, exists := accountGroupPeers[group.ID]; !exists {
			accountGroupPeers[group.ID] = make(map[string]struct{})
		}
	}

	updatedGroups := []string{}
	for _, user := range users {
		userPeers, err := transaction.GetUserPeers(ctx, store.LockingStrengthNone, accountID, user.Id)
		if err != nil {
			return false, false, err
		}

		for _, peer := range userPeers {
			for _, groupID := range user.AutoGroups {
				if _, exists := accountGroupPeers[groupID]; !exists {
					// we do not wanna create the groups here
					log.WithContext(ctx).Warnf("group %s does not exist for user group propagation", groupID)
					continue
				}
				if _, exists := accountGroupPeers[groupID][peer.ID]; exists {
					continue
				}
				if err := transaction.AddPeerToGroup(ctx, accountID, peer.ID, groupID); err != nil {
					return false, false, fmt.Errorf("error adding peer %s to group %s: %w", peer.ID, groupID, err)
				}
				updatedGroups = append(updatedGroups, groupID)
			}
		}
	}

	peersAffected, err = areGroupChangesAffectPeers(ctx, transaction, accountID, updatedGroups)
	if err != nil {
		return false, false, fmt.Errorf("error checking if group changes affect peers: %w", err)
	}

	return len(updatedGroups) > 0, peersAffected, nil
}

// reallocateAccountPeerIPs re-allocates all peer IPs when the network range changes
func (am *DefaultAccountManager) reallocateAccountPeerIPs(ctx context.Context, transaction store.Store, accountID string, newNetworkRange netip.Prefix) error {
	if !newNetworkRange.IsValid() {
		return nil
	}

	newIPNet := net.IPNet{
		IP:   newNetworkRange.Masked().Addr().AsSlice(),
		Mask: net.CIDRMask(newNetworkRange.Bits(), newNetworkRange.Addr().BitLen()),
	}

	account, err := transaction.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	account.Network.Net = newIPNet

	peers, err := transaction.GetAccountPeers(ctx, store.LockingStrengthNone, accountID, "", "")
	if err != nil {
		return err
	}

	var takenIPs []net.IP

	for _, peer := range peers {
		newIP, err := types.AllocatePeerIP(newIPNet, takenIPs)
		if err != nil {
			return status.Errorf(status.Internal, "allocate IP for peer %s: %v", peer.ID, err)
		}

		log.WithContext(ctx).Infof("reallocating peer %s IP from %s to %s due to network range change",
			peer.ID, peer.IP.String(), newIP.String())

		peer.IP = newIP
		takenIPs = append(takenIPs, newIP)
	}

	if err = transaction.SaveAccount(ctx, account); err != nil {
		return err
	}

	for _, peer := range peers {
		if err = transaction.SavePeer(ctx, accountID, peer); err != nil {
			return status.Errorf(status.Internal, "save updated peer %s: %v", peer.ID, err)
		}
	}

	log.WithContext(ctx).Infof("successfully re-allocated IPs for %d peers in account %s to network range %s",
		len(peers), accountID, newNetworkRange.String())

	return nil
}

func (am *DefaultAccountManager) validateIPForUpdate(account *types.Account, peers []*nbpeer.Peer, peerID string, newIP netip.Addr) error {
	if !account.Network.Net.Contains(newIP.AsSlice()) {
		return status.Errorf(status.InvalidArgument, "IP %s is not within the account network range %s", newIP.String(), account.Network.Net.String())
	}

	for _, peer := range peers {
		if peer.ID != peerID && peer.IP.Equal(newIP.AsSlice()) {
			return status.Errorf(status.InvalidArgument, "IP %s is already assigned to peer %s", newIP.String(), peer.ID)
		}
	}
	return nil
}

func (am *DefaultAccountManager) UpdatePeerIP(ctx context.Context, accountID, userID, peerID string, newIP netip.Addr) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Update)
	if err != nil {
		return fmt.Errorf("validate user permissions: %w", err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	updateNetworkMap, err := am.updatePeerIPInTransaction(ctx, accountID, userID, peerID, newIP)
	if err != nil {
		return fmt.Errorf("update peer IP transaction: %w", err)
	}

	if updateNetworkMap {
		am.BufferUpdateAccountPeers(ctx, accountID)
	}
	return nil
}

func (am *DefaultAccountManager) updatePeerIPInTransaction(ctx context.Context, accountID, userID, peerID string, newIP netip.Addr) (bool, error) {
	var updateNetworkMap bool
	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		account, err := transaction.GetAccount(ctx, accountID)
		if err != nil {
			return fmt.Errorf("get account: %w", err)
		}

		existingPeer, err := transaction.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
		if err != nil {
			return fmt.Errorf("get peer: %w", err)
		}

		if existingPeer.IP.Equal(newIP.AsSlice()) {
			return nil
		}

		peers, err := transaction.GetAccountPeers(ctx, store.LockingStrengthShare, accountID, "", "")
		if err != nil {
			return fmt.Errorf("get account peers: %w", err)
		}

		if err := am.validateIPForUpdate(account, peers, peerID, newIP); err != nil {
			return err
		}

		if err := am.savePeerIPUpdate(ctx, transaction, accountID, userID, existingPeer, newIP); err != nil {
			return err
		}

		updateNetworkMap = true
		return nil
	})
	return updateNetworkMap, err
}

func (am *DefaultAccountManager) savePeerIPUpdate(ctx context.Context, transaction store.Store, accountID, userID string, peer *nbpeer.Peer, newIP netip.Addr) error {
	log.WithContext(ctx).Infof("updating peer %s IP from %s to %s", peer.ID, peer.IP, newIP)

	settings, err := transaction.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("get account settings: %w", err)
	}
	dnsDomain := am.GetDNSDomain(settings)

	eventMeta := peer.EventMeta(dnsDomain)
	oldIP := peer.IP.String()

	peer.IP = newIP.AsSlice()
	err = transaction.SavePeer(ctx, accountID, peer)
	if err != nil {
		return fmt.Errorf("save peer: %w", err)
	}

	eventMeta["old_ip"] = oldIP
	eventMeta["ip"] = newIP.String()
	am.StoreEvent(ctx, userID, peer.ID, accountID, activity.PeerIPUpdated, eventMeta)

	return nil
}
