package server

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/idp"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/shared/management/domain"

	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/version"
)

type peerExpirationReason string

const (
	remoteJobsMinVer = "0.64.0"

	peerExpirationSessionExpired   peerExpirationReason = "session expiration"
	peerExpirationInactivity       peerExpirationReason = "inactivity timeout"
	peerExpirationValidationFailed peerExpirationReason = "failed integration validation"
	peerExpirationUserBlocked      peerExpirationReason = "blocked owner account"
)

// GetPeers returns peers visible to the user within an account.
// Users with "peers:read" see all peers. Otherwise, users see only their own peers, or none if restricted by account settings.
func (am *DefaultAccountManager) GetPeers(ctx context.Context, accountID, userID, nameFilter, ipFilter string) ([]*nbpeer.Peer, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return nil, err
	}

	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}

	if allowed {
		return am.Store.GetAccountPeers(ctx, store.LockingStrengthNone, accountID, nameFilter, ipFilter)
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get account settings: %w", err)
	}

	if user.IsRestrictable() && settings.RegularUsersViewBlocked {
		return []*nbpeer.Peer{}, nil
	}

	return am.Store.GetUserPeers(ctx, store.LockingStrengthNone, accountID, userID)
}

// MarkPeerConnected marks a peer as connected with optimistic-locked
// fencing on PeerStatus.SessionStartedAt. The sessionStartedAt argument
// is the start time of the gRPC sync stream that owns this update,
// expressed as Unix nanoseconds — only the call whose token is greater
// than what's stored wins. LastSeen is written by the database itself;
// we never pass it down.
//
// Disconnects use MarkPeerDisconnected and require the session to match
// exactly; see PeerStatus.SessionStartedAt for the protocol.
func (am *DefaultAccountManager) MarkPeerConnected(ctx context.Context, peerPubKey string, accountID string, sessionStartedAt int64, nmap *types.NetworkMap) error {
	start := time.Now()
	defer func() {
		am.metrics.AccountManagerMetrics().RecordPeerStatusUpdateDuration(telemetry.PeerStatusConnect, time.Since(start))
	}()

	peer, err := am.Store.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerPubKey)
	if err != nil {
		outcome := telemetry.PeerStatusError
		if s, ok := status.FromError(err); ok && s.Type() == status.NotFound {
			outcome = telemetry.PeerStatusPeerNotFound
		}
		am.metrics.AccountManagerMetrics().CountPeerStatusUpdate(telemetry.PeerStatusConnect, outcome)
		return err
	}

	updated, err := am.Store.MarkPeerConnectedIfNewerSession(ctx, accountID, peer.ID, sessionStartedAt)
	if err != nil {
		am.metrics.AccountManagerMetrics().CountPeerStatusUpdate(telemetry.PeerStatusConnect, telemetry.PeerStatusError)
		return err
	}
	if !updated {
		am.metrics.AccountManagerMetrics().CountPeerStatusUpdate(telemetry.PeerStatusConnect, telemetry.PeerStatusStale)
		log.WithContext(ctx).Tracef("peer %s already has a newer session in store, skipping connect", peer.ID)
		return nil
	}
	am.metrics.AccountManagerMetrics().CountPeerStatusUpdate(telemetry.PeerStatusConnect, telemetry.PeerStatusApplied)

	if err = am.schedulePeerExpirations(ctx, accountID, peer); err != nil {
		return err
	}

	// A login-expired peer reconnecting, or an embedded proxy peer flipping to
	// connected (which triggers SynthesizePrivateServiceZones), must refresh the
	// peers reachable from it. The embedded-proxy fan-out tolerates a dispatch error.
	if peer.Status != nil && peer.Status.LoginExpired {
		affectedPeerIDs := am.markConnectedAffectedPeers(ctx, accountID, peer.ID, nmap)
		if err = am.networkMapController.OnPeersUpdated(ctx, accountID, []string{peer.ID}, affectedPeerIDs); err != nil {
			return fmt.Errorf("notify network map controller of peer update: %w", err)
		}
	}
	if peer.ProxyMeta.Embedded {
		affectedPeerIDs := am.markConnectedAffectedPeers(ctx, accountID, peer.ID, nmap)
		if err := am.networkMapController.OnPeersUpdated(ctx, accountID, []string{peer.ID}, affectedPeerIDs); err != nil {
			log.WithContext(ctx).Warnf("notify network map controller of embedded proxy %s connect: %v", peer.ID, err)
		}
	}

	return nil
}

// schedulePeerExpirations reschedules the account's login/inactivity expiration
// timers for an SSO peer that just connected.
func (am *DefaultAccountManager) schedulePeerExpirations(ctx context.Context, accountID string, peer *nbpeer.Peer) error {
	if !peer.AddedWithSSOLogin() {
		return nil
	}
	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return err
	}
	if peer.LoginExpirationEnabled && settings.PeerLoginExpirationEnabled {
		am.schedulePeerLoginExpiration(ctx, accountID)
	}
	if peer.InactivityExpirationEnabled && settings.PeerInactivityExpirationEnabled {
		am.checkAndSchedulePeerInactivityExpiration(ctx, accountID)
	}
	return nil
}

// MarkPeerDisconnected marks a peer as disconnected, but only when the
// stored session token matches the one passed in. A mismatch means a
// newer stream has already taken ownership of the peer — disconnects from
// the older stream are ignored. LastSeen is written by the database.
func (am *DefaultAccountManager) MarkPeerDisconnected(ctx context.Context, peerPubKey string, accountID string, sessionStartedAt int64) error {
	start := time.Now()
	defer func() {
		am.metrics.AccountManagerMetrics().RecordPeerStatusUpdateDuration(telemetry.PeerStatusDisconnect, time.Since(start))
	}()

	peer, err := am.Store.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerPubKey)
	if err != nil {
		outcome := telemetry.PeerStatusError
		if s, ok := status.FromError(err); ok && s.Type() == status.NotFound {
			outcome = telemetry.PeerStatusPeerNotFound
		}
		am.metrics.AccountManagerMetrics().CountPeerStatusUpdate(telemetry.PeerStatusDisconnect, outcome)
		return err
	}

	updated, err := am.Store.MarkPeerDisconnectedIfSameSession(ctx, accountID, peer.ID, sessionStartedAt)
	if err != nil {
		am.metrics.AccountManagerMetrics().CountPeerStatusUpdate(telemetry.PeerStatusDisconnect, telemetry.PeerStatusError)
		return err
	}
	if !updated {
		am.metrics.AccountManagerMetrics().CountPeerStatusUpdate(telemetry.PeerStatusDisconnect, telemetry.PeerStatusStale)
		log.WithContext(ctx).Tracef("peer %s session token mismatch on disconnect (token=%d), skipping",
			peer.ID, sessionStartedAt)
		return nil
	}
	am.metrics.AccountManagerMetrics().CountPeerStatusUpdate(telemetry.PeerStatusDisconnect, telemetry.PeerStatusApplied)

	// Symmetric with MarkPeerConnected: when an embedded proxy peer goes
	// offline, refresh the peers that had synthesized records pointing at
	// it so they pull the stale entries instead of waiting out TTL.
	if peer.ProxyMeta.Embedded {
		changedPeerIDs := []string{peer.ID}
		affectedPeerIDs := am.resolveAffectedPeersForPeerChanges(ctx, am.Store, accountID, changedPeerIDs)
		if err := am.networkMapController.OnPeersUpdated(ctx, accountID, changedPeerIDs, affectedPeerIDs); err != nil {
			log.WithContext(ctx).Warnf("notify network map controller of embedded proxy %s disconnect: %v", peer.ID, err)
		}
	}

	if peer.AddedWithSSOLogin() && peer.InactivityExpirationEnabled {
		settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			log.WithContext(ctx).Warnf("failed getting account settings to schedule inactivity expiration for peer %s: %v", peer.ID, err)
		} else if settings.PeerInactivityExpirationEnabled {
			am.checkAndSchedulePeerInactivityExpiration(ctx, accountID)
		}
	}

	return nil
}

// resolvePeerLocation looks up the geo location for realIP, returning nil when
// there is nothing to apply: geo disabled, no real IP, the IP is unchanged from
// what the peer already has, or the lookup failed. Geo lookups are skipped on
// same-IP reconnects since they are comparatively expensive. The returned value
// is applied by Peer.UpdateMetaIfNew so the change is persisted by its peer save.
func (am *DefaultAccountManager) resolvePeerLocation(ctx context.Context, peer *nbpeer.Peer, realIP net.IP) *nbpeer.Location {
	if am.geo == nil || realIP == nil {
		return nil
	}
	location, err := am.geo.Lookup(realIP)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to get location for peer %s realip: [%s]: %v", peer.ID, realIP.String(), err)
		return nil
	}
	if peer.Location.ConnectionIP != nil && peer.Location.ConnectionIP.Equal(realIP) && peer.Location.GeoNameID == location.City.GeonameID {
		return nil
	}
	return &nbpeer.Location{
		ConnectionIP: realIP,
		CountryCode:  location.Country.ISOCode,
		CityName:     location.City.Names.En,
		GeoNameID:    location.City.GeonameID,
	}
}

// UpdatePeer updates peer. Only Peer.Name, Peer.SSHEnabled, Peer.LoginExpirationEnabled and Peer.InactivityExpirationEnabled can be updated.
func (am *DefaultAccountManager) UpdatePeer(ctx context.Context, accountID, userID string, update *nbpeer.Peer) (*nbpeer.Peer, error) {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	var peer *nbpeer.Peer
	var settings *types.Settings
	var peerGroupList []string
	var peerLabelChanged bool
	var sshChanged bool
	var loginExpirationChanged bool
	var inactivityExpirationChanged bool
	var dnsDomain string

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		peer, err = transaction.GetPeerByID(ctx, store.LockingStrengthUpdate, accountID, update.ID)
		if err != nil {
			return err
		}

		if peer.ProxyMeta.Embedded {
			return fmt.Errorf("not allowed to update peer")
		}

		settings, err = transaction.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			return err
		}

		peerGroupList, err = getPeerGroupIDs(ctx, transaction, accountID, update.ID)
		if err != nil {
			return err
		}

		dnsDomain = am.networkMapController.GetDNSDomain(settings)

		update, _, err = am.integratedPeerValidator.ValidatePeer(ctx, update, peer, userID, accountID, dnsDomain, peerGroupList, settings.Extra)
		if err != nil {
			return err
		}

		if peer.Name != update.Name {
			var newLabel string

			newLabel, err = nbdns.GetParsedDomainLabel(update.Name)
			if err != nil {
				newLabel = ""
			} else {
				_, err := transaction.GetPeerIdByLabel(ctx, store.LockingStrengthNone, accountID, newLabel)
				if err == nil {
					newLabel = ""
				}
			}

			if newLabel == "" {
				newLabel, err = getPeerIPDNSLabel(peer.IP, update.Name)
				if err != nil {
					return fmt.Errorf("failed to get free DNS label: %w", err)
				}
			}
			peer.Name = update.Name
			peer.DNSLabel = newLabel
			peerLabelChanged = true
		}

		if peer.SSHEnabled != update.SSHEnabled {
			peer.SSHEnabled = update.SSHEnabled
			sshChanged = true
		}

		if peer.LoginExpirationEnabled != update.LoginExpirationEnabled {
			if !peer.AddedWithSSOLogin() {
				return status.Errorf(status.PreconditionFailed, "this peer hasn't been added with the SSO login, therefore the login expiration can't be updated")
			}
			peer.LoginExpirationEnabled = update.LoginExpirationEnabled
			loginExpirationChanged = true
		}

		if peer.InactivityExpirationEnabled != update.InactivityExpirationEnabled {
			if !peer.AddedWithSSOLogin() {
				return status.Errorf(status.PreconditionFailed, "this peer hasn't been added with the SSO login, therefore the inactivity expiration can't be updated")
			}
			peer.InactivityExpirationEnabled = update.InactivityExpirationEnabled
			inactivityExpirationChanged = true
		}

		if err = transaction.IncrementNetworkSerial(ctx, accountID); err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return transaction.SavePeer(ctx, accountID, peer)
	})
	if err != nil {
		return nil, err
	}

	if sshChanged {
		event := activity.PeerSSHEnabled
		if !peer.SSHEnabled {
			event = activity.PeerSSHDisabled
		}
		am.StoreEvent(ctx, userID, peer.IP.String(), accountID, event, peer.EventMeta(dnsDomain))
	}

	if peerLabelChanged {
		am.StoreEvent(ctx, userID, peer.ID, accountID, activity.PeerRenamed, peer.EventMeta(dnsDomain))
	}

	if loginExpirationChanged {
		event := activity.PeerLoginExpirationEnabled
		if !peer.LoginExpirationEnabled {
			event = activity.PeerLoginExpirationDisabled
		}
		am.StoreEvent(ctx, userID, peer.IP.String(), accountID, event, peer.EventMeta(dnsDomain))

		if peer.AddedWithSSOLogin() && peer.LoginExpirationEnabled && settings.PeerLoginExpirationEnabled {
			am.peerLoginExpiry.Cancel(ctx, []string{accountID})
			am.schedulePeerLoginExpiration(ctx, accountID)
		}
	}

	if inactivityExpirationChanged {
		event := activity.PeerInactivityExpirationEnabled
		if !peer.InactivityExpirationEnabled {
			event = activity.PeerInactivityExpirationDisabled
		}
		am.StoreEvent(ctx, userID, peer.IP.String(), accountID, event, peer.EventMeta(dnsDomain))

		if peer.AddedWithSSOLogin() && peer.InactivityExpirationEnabled && settings.PeerInactivityExpirationEnabled {
			am.checkAndSchedulePeerInactivityExpiration(ctx, accountID)
		}
	}

	changedPeerIDs := []string{peer.ID}
	affectedPeerIDs := am.resolveAffectedPeersForPeerChanges(ctx, am.Store, accountID, changedPeerIDs)
	affectedPeerIDs = append(affectedPeerIDs, peer.ID)
	err = am.networkMapController.OnPeersUpdated(ctx, accountID, changedPeerIDs, affectedPeerIDs)
	if err != nil {
		return nil, fmt.Errorf("notify network map controller of peer update: %w", err)
	}

	return peer, nil
}

func (am *DefaultAccountManager) CreatePeerJob(ctx context.Context, accountID, peerID, userID string, job *types.Job) error {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.RemoteJobs, operations.Create)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	p, err := am.Store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		return err
	}

	if p.AccountID != accountID {
		return status.NewPeerNotPartOfAccountError()
	}

	meetMinVer, err := posture.MeetsMinVersion(remoteJobsMinVer, p.Meta.WtVersion)
	if !version.IsDevelopmentVersion(p.Meta.WtVersion) && (!meetMinVer || err != nil) {
		return status.Errorf(status.PreconditionFailed, "peer version %s does not meet the minimum required version %s for remote jobs", p.Meta.WtVersion, remoteJobsMinVer)
	}

	if !am.jobManager.IsPeerConnected(peerID) {
		return status.Errorf(status.BadRequest, "peer not connected")
	}

	// check if already has pending jobs
	// todo: The job checks here are not protected. The user can run this function from multiple threads,
	// and each thread can think there is no job yet. This means entries in the pending job map will be overwritten,
	// and only one will be kept, but potentially another one will overwrite it in the queue.
	if am.jobManager.IsPeerHasPendingJobs(peerID) {
		return status.Errorf(status.BadRequest, "peer already has pending job")
	}

	jobStream, err := job.ToStreamJobRequest()
	if err != nil {
		return status.Errorf(status.BadRequest, "invalid job request %v", err)
	}

	// try sending job first
	if err := am.jobManager.SendJob(ctx, accountID, peerID, jobStream); err != nil {
		return status.Errorf(status.Internal, "failed to send job: %v", err)
	}

	var peer *nbpeer.Peer
	var eventsToStore func()

	// persist job in DB only if send succeeded
	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		peer, err = transaction.GetPeerByID(ctx, store.LockingStrengthUpdate, accountID, peerID)
		if err != nil {
			return err
		}
		if err := transaction.CreatePeerJob(ctx, job); err != nil {
			return err
		}

		jobMeta := map[string]any{
			"for_peer_name": peer.Name,
			"job_type":      job.Workload.Type,
		}

		eventsToStore = func() {
			am.StoreEvent(ctx, userID, peer.ID, accountID, activity.JobCreatedByUser, jobMeta)
		}
		return nil
	})
	if err != nil {
		return err
	}
	eventsToStore()
	return nil
}

func (am *DefaultAccountManager) GetAllPeerJobs(ctx context.Context, accountID, userID, peerID string) ([]*types.Job, error) {
	// todo: Create permissions for job
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.RemoteJobs, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	peerAccountID, err := am.Store.GetAccountIDByPeerID(ctx, store.LockingStrengthNone, peerID)
	if err != nil {
		return nil, err
	}

	if peerAccountID != accountID {
		return nil, status.NewPeerNotPartOfAccountError()
	}

	accountJobs, err := am.Store.GetPeerJobs(ctx, accountID, peerID)
	if err != nil {
		return nil, err
	}

	return accountJobs, nil
}

func (am *DefaultAccountManager) GetPeerJobByID(ctx context.Context, accountID, userID, peerID, jobID string) (*types.Job, error) {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.RemoteJobs, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	peerAccountID, err := am.Store.GetAccountIDByPeerID(ctx, store.LockingStrengthNone, peerID)
	if err != nil {
		return nil, err
	}

	if peerAccountID != accountID {
		return nil, status.NewPeerNotPartOfAccountError()
	}

	job, err := am.Store.GetPeerJobByID(ctx, accountID, jobID)
	if err != nil {
		return nil, err
	}

	return job, nil
}

// DeletePeer removes peer from the account by its IP
func (am *DefaultAccountManager) DeletePeer(ctx context.Context, accountID, peerID, userID string) error {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	peerAccountID, err := am.Store.GetAccountIDByPeerID(ctx, store.LockingStrengthNone, peerID)
	if err != nil {
		return err
	}

	if peerAccountID != accountID {
		return status.NewPeerNotPartOfAccountError()
	}

	serviceID, err := am.serviceManager.GetServiceIDByTargetID(ctx, accountID, peerID)
	if err != nil {
		return fmt.Errorf("failed to check if resource is used by service: %w", err)
	}
	if serviceID != "" {
		return status.NewPeerInUseError(peerID, serviceID)
	}

	change := affectedpeers.Change{ChangedPeerIDs: []string{peerID}}
	settings, eventsToStore, snap, err := am.deletePeerInTransaction(ctx, accountID, userID, peerID, change)
	if err != nil {
		return err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	if err = am.integratedPeerValidator.PeerDeleted(ctx, accountID, peerID, settings.Extra); err != nil {
		log.WithContext(ctx).Errorf("failed to delete peer %s from integrated validator: %v", peerID, err)
	}

	affectedPeerIDs := snap.Expand(ctx, accountID, change)
	if err = am.networkMapController.OnPeersDeleted(ctx, accountID, []string{peerID}, affectedPeerIDs); err != nil {
		log.WithContext(ctx).Errorf("failed to delete peer %s from network map: %v", peerID, err)
	}

	return nil
}

// deletePeerInTransaction loads the peer + settings, captures the affected-peers
// snapshot (before the delete, while the peer's group memberships still exist),
// then deletes the peer and bumps the network serial — all in one transaction.
func (am *DefaultAccountManager) deletePeerInTransaction(ctx context.Context, accountID, userID, peerID string, change affectedpeers.Change) (*types.Settings, []func(), *affectedpeers.Snapshot, error) {
	var settings *types.Settings
	var eventsToStore []func()
	var snap *affectedpeers.Snapshot

	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		peer, err := transaction.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
		if err != nil {
			return err
		}

		settings, err = transaction.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			return err
		}

		if err = am.validatePeerDelete(ctx, transaction, accountID, peerID); err != nil {
			return err
		}

		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		if eventsToStore, err = deletePeers(ctx, am, transaction, accountID, userID, []*nbpeer.Peer{peer}, settings); err != nil {
			return fmt.Errorf("failed to delete peer: %w", err)
		}

		if err = transaction.IncrementNetworkSerial(ctx, accountID); err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	return settings, eventsToStore, snap, err
}

// GetNetworkMap returns Network map for a given peer (omits original peer from the Peers result)
func (am *DefaultAccountManager) GetNetworkMap(ctx context.Context, peerID string) (*types.NetworkMap, error) {
	return am.networkMapController.GetNetworkMap(ctx, peerID)
}

// GetPeerNetwork returns the Network for a given peer
func (am *DefaultAccountManager) GetPeerNetwork(ctx context.Context, peerID string) (*types.Network, error) {
	account, err := am.Store.GetAccountByPeerID(ctx, peerID)
	if err != nil {
		return nil, err
	}

	return account.Network.Copy(), err
}

// peerWillHaveIPv6 checks whether the peer's future group memberships
// (auto-groups + allGroupID) overlap with IPv6EnabledGroups.
func peerWillHaveIPv6(settings *types.Settings, groupsToAdd []string, allGroupID string) bool {
	enabledSet := make(map[string]struct{}, len(settings.IPv6EnabledGroups))
	for _, gid := range settings.IPv6EnabledGroups {
		enabledSet[gid] = struct{}{}
	}

	if allGroupID != "" {
		if _, ok := enabledSet[allGroupID]; ok {
			return true
		}
	}
	for _, gid := range groupsToAdd {
		if _, ok := enabledSet[gid]; ok {
			return true
		}
	}
	return false
}

type peerAddAuthConfig struct {
	AccountID           string
	SetupKeyID          string
	SetupKeyName        string
	GroupsToAdd         []string
	AllowExtraDNSLabels bool
	Ephemeral           bool
}

func (am *DefaultAccountManager) processPeerAddAuth(ctx context.Context, accountID, userID, encodedHashedKey string, peer *nbpeer.Peer, temporary, addedByUser, addedBySetupKey bool, opEvent *activity.Event) (*peerAddAuthConfig, error) {
	config := &peerAddAuthConfig{
		AccountID: accountID,
		Ephemeral: peer.Ephemeral,
	}

	switch {
	case addedByUser:
		if err := am.handleUserAddedPeer(ctx, accountID, userID, temporary, opEvent, config); err != nil {
			return nil, err
		}
	case addedBySetupKey:
		if err := am.handleSetupKeyAddedPeer(ctx, encodedHashedKey, peer, opEvent, config); err != nil {
			return nil, err
		}
	default:
		if peer.ProxyMeta.Embedded {
			log.WithContext(ctx).Debugf("adding peer for proxy embedded, accountID: %s", accountID)
		} else {
			log.WithContext(ctx).Warnf("adding peer without setup key or userID, accountID: %s", accountID)
		}
	}

	opEvent.AccountID = config.AccountID
	if temporary {
		config.Ephemeral = true
	}

	return config, nil
}

func (am *DefaultAccountManager) handleUserAddedPeer(ctx context.Context, accountID, userID string, temporary bool, opEvent *activity.Event, config *peerAddAuthConfig) error {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return status.Errorf(status.NotFound, "failed adding new peer: user not found")
	}
	if user.PendingApproval {
		return status.Errorf(status.PermissionDenied, "user pending approval cannot add peers")
	}

	if temporary {
		allowed, _, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Create)
		if err != nil {
			return status.NewPermissionValidationError(err)
		}
		if !allowed {
			return status.NewPermissionDeniedError()
		}
	} else {
		config.AccountID = user.AccountID
		config.GroupsToAdd = user.AutoGroups
	}

	opEvent.InitiatorID = userID
	opEvent.Activity = activity.PeerAddedByUser
	return nil
}

func (am *DefaultAccountManager) handleSetupKeyAddedPeer(ctx context.Context, encodedHashedKey string, peer *nbpeer.Peer, opEvent *activity.Event, config *peerAddAuthConfig) error {
	sk, err := am.Store.GetSetupKeyBySecret(ctx, store.LockingStrengthNone, encodedHashedKey)
	if err != nil {
		return status.Errorf(status.NotFound, "couldn't add peer: setup key is invalid")
	}

	if !sk.IsValid() {
		return status.Errorf(status.NotFound, "couldn't add peer: setup key is invalid")
	}

	if !sk.AllowExtraDNSLabels && len(peer.ExtraDNSLabels) > 0 {
		return status.Errorf(status.PreconditionFailed, "couldn't add peer: setup key doesn't allow extra DNS labels")
	}

	opEvent.InitiatorID = sk.Id
	opEvent.Activity = activity.PeerAddedWithSetupKey
	config.GroupsToAdd = sk.AutoGroups
	config.Ephemeral = sk.Ephemeral
	config.SetupKeyID = sk.Id
	config.SetupKeyName = sk.Name
	config.AllowExtraDNSLabels = sk.AllowExtraDNSLabels
	config.AccountID = sk.AccountID

	return nil
}

// AddPeer adds a new peer to the Store.
// Each Account has a list of pre-authorized SetupKey and if no Account has a given key err with a code status.PermissionDenied
// will be returned, meaning the setup key is invalid or not found.
// If a User ID is provided, it means that we passed the authentication using JWT, then we look for account by User ID and register the peer
// to it. We also add the User ID to the peer metadata to identify registrant. If no userID provided, then fail with status.PermissionDenied
// Each new Peer will be assigned a new next net.IP from the Account.Network and Account.Network.LastIP will be updated (IP's are not reused).
// The peer property is just a placeholder for the Peer properties to pass further
func (am *DefaultAccountManager) AddPeer(ctx context.Context, accountID, setupKey, userID string, peer *nbpeer.Peer, temporary bool) (*nbpeer.Peer, *types.Network, []*posture.Checks, bool, error) {
	if setupKey == "" && userID == "" && !peer.ProxyMeta.Embedded {
		// no auth method provided => reject access
		return nil, nil, nil, false, status.ErrNoAuthMethodProvided
	}

	upperKey := strings.ToUpper(setupKey)
	hashedKey := sha256.Sum256([]byte(upperKey))
	encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])
	addedByUser := len(userID) > 0
	addedBySetupKey := len(setupKey) > 0

	// This is a handling for the case when the same machine (with the same WireGuard pub key) tries to register twice.
	// Such case is possible when AddPeer function takes long time to finish after AcquireWriteLockByUID (e.g., database is slow)
	// and the peer disconnects with a timeout and tries to register again.
	// We just check if this machine has been registered before and reject the second registration.
	// The connecting peer should be able to recover with a retry.
	_, err := am.Store.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peer.Key)
	if err == nil {
		return nil, nil, nil, false, status.Errorf(status.PreconditionFailed, "peer has been already registered")
	}

	opEvent := &activity.Event{
		Timestamp: time.Now().UTC(),
	}

	var newPeer *nbpeer.Peer

	peerAddConfig, err := am.processPeerAddAuth(ctx, accountID, userID, encodedHashedKey, peer, temporary, addedByUser, addedBySetupKey, opEvent)
	if err != nil {
		return nil, nil, nil, false, err
	}
	accountID = peerAddConfig.AccountID
	ephemeral := peerAddConfig.Ephemeral

	if (strings.ToLower(peer.Meta.Hostname) == "iphone" || strings.ToLower(peer.Meta.Hostname) == "ipad") && userID != "" {
		if am.idpManager != nil {
			userdata, err := am.idpManager.GetUserDataByID(ctx, userID, idp.AppMetadata{WTAccountID: accountID})
			if err == nil && userdata != nil {
				peer.Meta.Hostname = fmt.Sprintf("%s-%s", peer.Meta.Hostname, strings.Split(userdata.Email, "@")[0])
			}
		}
	}

	if err := domain.ValidateDomainsList(peer.ExtraDNSLabels); err != nil {
		return nil, nil, nil, false, status.Errorf(status.InvalidArgument, "invalid extra DNS labels: %v", err)
	}

	registrationTime := time.Now().UTC()
	newPeer = &nbpeer.Peer{
		ID:                          xid.New().String(),
		AccountID:                   accountID,
		Key:                         peer.Key,
		Meta:                        peer.Meta,
		Name:                        peer.Meta.Hostname,
		UserID:                      userID,
		Status:                      &nbpeer.PeerStatus{Connected: false, LastSeen: registrationTime},
		SSHEnabled:                  false,
		SSHKey:                      peer.SSHKey,
		LastLogin:                   &registrationTime,
		CreatedAt:                   registrationTime,
		LoginExpirationEnabled:      addedByUser && !temporary,
		Ephemeral:                   ephemeral,
		ProxyMeta:                   peer.ProxyMeta,
		Location:                    peer.Location,
		InactivityExpirationEnabled: addedByUser && !temporary,
		ExtraDNSLabels:              peer.ExtraDNSLabels,
		AllowExtraDNSLabels:         peerAddConfig.AllowExtraDNSLabels,
	}
	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("failed to get account settings: %w", err)
	}

	if am.geo != nil && newPeer.Location.ConnectionIP != nil {
		location, err := am.geo.Lookup(newPeer.Location.ConnectionIP)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to get location for new peer realip: [%s]: %v", newPeer.Location.ConnectionIP.String(), err)
		} else {
			newPeer.Location.CountryCode = location.Country.ISOCode
			newPeer.Location.CityName = location.City.Names.En
			newPeer.Location.GeoNameID = location.City.GeonameID
		}
	}

	newPeer = am.integratedPeerValidator.PreparePeer(ctx, accountID, newPeer, peerAddConfig.GroupsToAdd, settings.Extra, temporary)

	network, err := am.Store.GetAccountNetwork(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("failed getting network: %w", err)
	}

	maxAttempts := 10
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		netPrefix, err := netip.ParsePrefix(network.Net.String())
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("parse network prefix: %w", err)
		}
		freeIP, err := types.AllocateRandomPeerIP(netPrefix)
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("failed to get free IP: %w", err)
		}

		var freeLabel string
		if ephemeral || attempt > 1 {
			freeLabel, err = getPeerIPDNSLabel(freeIP, peer.Meta.Hostname)
			if err != nil {
				return nil, nil, nil, false, fmt.Errorf("failed to get free DNS label: %w", err)
			}
		} else {
			freeLabel, err = nbdns.GetParsedDomainLabel(peer.Meta.Hostname)
			if err != nil {
				return nil, nil, nil, false, fmt.Errorf("failed to get free DNS label: %w", err)
			}
		}
		newPeer.DNSLabel = freeLabel
		newPeer.IP = freeIP

		if len(settings.IPv6EnabledGroups) > 0 && network.NetV6.IP != nil {
			// Embedded proxy peers are not group members but participate in any
			// IPv6-enabled overlay so reverse-proxy traffic reaches v6-only peers.
			allocate := peer.ProxyMeta.Embedded
			if !allocate {
				var allGroupID string
				if allGroup, err := am.Store.GetGroupByName(ctx, store.LockingStrengthNone, accountID, types.GroupAllName); err == nil {
					allGroupID = allGroup.ID
				} else {
					log.WithContext(ctx).Debugf("get All group for IPv6 allocation: %v", err)
				}
				allocate = peerWillHaveIPv6(settings, peerAddConfig.GroupsToAdd, allGroupID)
			}
			if allocate {
				v6Prefix, err := netip.ParsePrefix(network.NetV6.String())
				if err != nil {
					return nil, nil, nil, false, fmt.Errorf("parse IPv6 prefix: %w", err)
				}
				freeIPv6, err := types.AllocateRandomPeerIPv6(v6Prefix)
				if err != nil {
					return nil, nil, nil, false, fmt.Errorf("allocate peer IPv6: %w", err)
				}
				newPeer.IPv6 = freeIPv6
			}
		}

		err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
			err = transaction.AddPeerToAccount(ctx, newPeer)
			if err != nil {
				return err
			}

			if len(peerAddConfig.GroupsToAdd) > 0 {
				for _, g := range peerAddConfig.GroupsToAdd {
					err = transaction.AddPeerToGroup(ctx, newPeer.AccountID, newPeer.ID, g)
					if err != nil {
						return err
					}
				}
			}

			if !peer.ProxyMeta.Embedded {
				err = transaction.AddPeerToAllGroup(ctx, accountID, newPeer.ID)
				if err != nil {
					return fmt.Errorf("failed adding peer to All group: %w", err)
				}
			}

			switch {
			case addedByUser:
				err := transaction.SaveUserLastLogin(ctx, accountID, userID, newPeer.GetLastLogin())
				if err != nil {
					log.WithContext(ctx).Debugf("failed to update user last login: %v", err)
				}
			case addedBySetupKey:
				sk, err := transaction.GetSetupKeyBySecret(ctx, store.LockingStrengthUpdate, encodedHashedKey)
				if err != nil {
					return fmt.Errorf("failed to get setup key: %w", err)
				}

				// we validate at the end to not block the setup key for too long
				if !sk.IsValid() {
					return status.Errorf(status.PreconditionFailed, "couldn't add peer: setup key is invalid")
				}

				err = transaction.IncrementSetupKeyUsage(ctx, peerAddConfig.SetupKeyID)
				if err != nil {
					return fmt.Errorf("failed to increment setup key usage: %w", err)
				}
			}

			err = transaction.IncrementNetworkSerial(ctx, accountID)
			if err != nil {
				return fmt.Errorf("failed to increment network serial: %w", err)
			}

			if ephemeral {
				// we should track ephemeral peers to be able to clean them if the peer doesn't sync and isn't marked as connected
				am.networkMapController.TrackEphemeralPeer(ctx, newPeer)
			}

			log.WithContext(ctx).Debugf("Peer %s added to account %s", newPeer.ID, accountID)
			return nil
		})
		if err == nil {
			break
		}

		if isUniqueConstraintError(err) {
			log.WithContext(ctx).WithFields(log.Fields{"dns_label": freeLabel, "ip": freeIP}).Tracef("Failed to add peer in attempt %d, retrying: %v", attempt, err)
			continue
		}

		return nil, nil, nil, false, fmt.Errorf("failed to add peer to database: %w", err)
	}
	if newPeer == nil {
		return nil, nil, nil, false, fmt.Errorf("new peer is nil")
	}

	opEvent.TargetID = newPeer.ID
	opEvent.Meta = newPeer.EventMeta(am.networkMapController.GetDNSDomain(settings))
	if !addedByUser {
		opEvent.Meta["setup_key_name"] = peerAddConfig.SetupKeyName
	}
	requiresApproval := newPeer.Status != nil && newPeer.Status.RequiresApproval
	if requiresApproval {
		opEvent.Meta["pending_approval"] = true
	}

	if !temporary {
		am.StoreEvent(ctx, opEvent.InitiatorID, opEvent.TargetID, opEvent.AccountID, opEvent.Activity, opEvent.Meta)
	}

	network, postureChecks, enableSSH, err := getPeerLoginInfo(ctx, am.Store, accountID, newPeer, !requiresApproval)
	if err != nil {
		return nil, nil, nil, false, err
	}

	changedPeerIDs := []string{newPeer.ID}
	affectedPeerIDs := am.resolveAffectedPeersForPeerChanges(ctx, am.Store, accountID, changedPeerIDs)
	if err := am.networkMapController.OnPeersAdded(ctx, accountID, changedPeerIDs, affectedPeerIDs); err != nil {
		log.WithContext(ctx).Errorf("failed to update network map cache for peer %s: %v", newPeer.ID, err)
	}

	return newPeer, network, postureChecks, enableSSH, nil
}

func getPeerIPDNSLabel(ip netip.Addr, peerHostName string) (string, error) {
	if !ip.Is4() {
		return "", fmt.Errorf("DNS label generation requires an IPv4 address, got %s", ip)
	}
	b := ip.As4()

	dnsName, err := nbdns.GetParsedDomainLabel(peerHostName)
	if err != nil {
		return "", fmt.Errorf("failed to parse peer host name %s: %w", peerHostName, err)
	}

	return fmt.Sprintf("%s-%d-%d", dnsName, b[2], b[3]), nil
}

// SyncPeer checks whether peer is eligible for receiving NetworkMap (authenticated) and returns its NetworkMap if eligible
func (am *DefaultAccountManager) SyncPeer(ctx context.Context, sync types.PeerSync, accountID string) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, int64, error) {
	var peer *nbpeer.Peer
	var ipv6CapabilityChanged bool
	var metaDiff nbpeer.MetaDiff
	var err error

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		peer, err = transaction.GetPeerByPeerPubKey(ctx, store.LockingStrengthUpdate, sync.WireGuardPubKey)
		if err != nil {
			return status.NewPeerNotRegisteredError()
		}

		if peer.UserID != "" {
			user, err := transaction.GetUserByUserID(ctx, store.LockingStrengthNone, peer.UserID)
			if err != nil {
				return err
			}

			if err = checkIfPeerOwnerIsBlocked(peer, user); err != nil {
				return err
			}
		}

		if peerLoginExpired(ctx, peer, settings) {
			return status.NewPeerLoginExpiredError()
		}

		oldHasIPv6Cap := peer.HasCapability(nbpeer.PeerCapabilityIPv6Overlay)
		newLocation := am.resolvePeerLocation(ctx, peer, sync.RealIP)
		metaDiff = peer.UpdateMetaIfNew(ctx, sync.Meta, newLocation)
		ipv6CapabilityChanged = oldHasIPv6Cap != peer.HasCapability(nbpeer.PeerCapabilityIPv6Overlay)
		if metaDiff.Updated() {
			am.metrics.AccountManagerMetrics().CountPeerMetUpdate()
			log.WithContext(ctx).Tracef("peer %s metadata updated", peer.ID)
			if err = transaction.SavePeer(ctx, accountID, peer); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, 0, err
	}

	peerGroupIDs, err := getPeerGroupIDs(ctx, am.Store, accountID, peer.ID)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	peerNotValid, isStatusChanged, err := am.integratedPeerValidator.IsNotValidPeer(ctx, accountID, peer, peerGroupIDs, settings.Extra)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	nmap, resPostureChecks, dnsFwdPort, err := am.networkMapController.GetValidatedPeerWithMap(ctx, peerNotValid, accountID, peer.ID)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	metaDiffAffectsPosture := posture.AffectsPosture(ctx, &metaDiff, resPostureChecks)
	if requiresPeerUpdate(ctx, isStatusChanged, sync.UpdateAccountPeers, ipv6CapabilityChanged, metaDiffAffectsPosture, metaDiff.VersionChanged(), metaDiff.HostnameChanged()) {
		changedPeerIDs := []string{peer.ID}
		affectedPeerIDs := am.syncPeerAffectedPeers(ctx, accountID, peer.ID, nmap, peerNotValid, metaDiffAffectsPosture)
		if err = am.networkMapController.OnPeersUpdated(ctx, accountID, changedPeerIDs, affectedPeerIDs); err != nil {
			return nil, nil, nil, 0, fmt.Errorf("notify network map controller of peer update: %w", err)
		}
	}

	return peer, nmap, resPostureChecks, dnsFwdPort, nil
}

func requiresPeerUpdate(ctx context.Context, isStatusChanged, updateAccountPeers, ipv6CapabilityChanged, metaDiffAffectsPosture, versionChanged, hostname bool) bool {
	var reason string
	switch {
	case isStatusChanged:
		reason = "status changed"
	case updateAccountPeers:
		reason = "update account peers"
	case ipv6CapabilityChanged:
		reason = "ipv6 capability changed"
	case metaDiffAffectsPosture:
		reason = "meta diff affects posture"
	case versionChanged:
		reason = "version changed"
	case hostname:
		reason = "hostname changed"
	default:
		return false
	}

	log.WithContext(ctx).Tracef("peer update required: %s", reason)
	return true
}

// syncPeerAffectedPeers resolves the peers affected by a SyncPeer change. The
// peer's own validated network map is bidirectional for policy and routing
// reachability, so when the peer stays valid and no source-posture gate is in
// play it already lists every affected peer — reuse it and skip the full
// dependency walk. Posture checks gate the source side of a policy only, so a
// metadata change that flips a posture result removes this peer from others'
// maps asymmetrically; that case (and an invalid peer, whose map is empty) falls
// back to the resolver.
func (am *DefaultAccountManager) syncPeerAffectedPeers(ctx context.Context, accountID, peerID string, nmap *types.NetworkMap, peerNotValid, metaChangeAffectedPosture bool) []string {
	if peerNotValid || metaChangeAffectedPosture {
		return am.resolveAffectedPeersForPeerChanges(ctx, am.Store, accountID, []string{peerID})
	}
	return affectedPeerIDsFromNetworkMap(nmap, peerID)
}

// markConnectedAffectedPeers resolves the peers affected when a peer connects
// (login-expiry reconnect or embedded-proxy connect). The connecting peer's
// network map already lists them bidirectionally — the synthesized
// private-service policy puts proxy access-group members in the proxy peer's own
// map, and these edges carry no source-posture gate. An invalid peer has an
// empty map, so fall back to the resolver in that case.
func (am *DefaultAccountManager) markConnectedAffectedPeers(ctx context.Context, accountID, peerID string, nmap *types.NetworkMap) []string {
	if nmap == nil || len(nmap.Peers)+len(nmap.OfflinePeers) == 0 {
		return am.resolveAffectedPeersForPeerChanges(ctx, am.Store, accountID, []string{peerID})
	}
	return affectedPeerIDsFromNetworkMap(nmap, peerID)
}

func (am *DefaultAccountManager) handlePeerLoginNotFound(ctx context.Context, login types.PeerLogin, err error) (*nbpeer.Peer, *types.Network, []*posture.Checks, bool, error) {
	if errStatus, ok := status.FromError(err); ok && errStatus.Type() == status.NotFound {
		// we couldn't find this peer by its public key which can mean that peer hasn't been registered yet.
		// Try registering it.
		newPeer := &nbpeer.Peer{
			Key:            login.WireGuardPubKey,
			Meta:           login.Meta,
			SSHKey:         login.SSHKey,
			Location:       nbpeer.Location{ConnectionIP: login.ConnectionIP},
			ExtraDNSLabels: login.ExtraDNSLabels,
		}

		return am.AddPeer(ctx, "", login.SetupKey, login.UserID, newPeer, false)
	}

	log.WithContext(ctx).Errorf("failed while logging in peer %s: %v", login.WireGuardPubKey, err)
	return nil, nil, nil, false, status.Errorf(status.Internal, "failed while logging in peer")
}

// LoginPeer logs in or registers a peer.
// If peer doesn't exist the function checks whether a setup key or a user is present and registers a new peer if so.
func (am *DefaultAccountManager) LoginPeer(ctx context.Context, login types.PeerLogin) (*nbpeer.Peer, *types.Network, []*posture.Checks, bool, error) {
	accountID, err := am.Store.GetAccountIDByPeerPubKey(ctx, login.WireGuardPubKey)
	if err != nil {
		return am.handlePeerLoginNotFound(ctx, login, err)
	}

	// when the client sends a login request with a JWT which is used to get the user ID,
	// it means that the client has already checked if it needs login and had been through the SSO flow
	// so, we can skip this check and directly proceed with the login
	if login.UserID == "" {
		err = am.checkIFPeerNeedsLoginWithoutLock(ctx, accountID, login)
		if err != nil {
			return nil, nil, nil, false, err
		}
	}

	var peer *nbpeer.Peer
	var shouldStorePeer, shouldUpdatePeers bool
	var peerGroupIDs []string

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, nil, false, err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		peer, err = transaction.GetPeerByPeerPubKey(ctx, store.LockingStrengthUpdate, login.WireGuardPubKey)
		if err != nil {
			return err
		}

		if login.UserID != "" {
			if peer.UserID != login.UserID {
				log.Warnf("user mismatch when logging in peer %s: peer user %s, login user %s ", peer.ID, peer.UserID, login.UserID)
				return status.NewPeerLoginMismatchError()
			}

			changed, err := am.handleUserPeer(ctx, transaction, peer, settings)
			if err != nil {
				return err
			}

			if changed {
				shouldStorePeer = true
				shouldUpdatePeers = true
			}
		}

		if peer.SSHKey != login.SSHKey {
			peer.SSHKey = login.SSHKey
			shouldStorePeer = true
		}

		if !peer.AllowExtraDNSLabels && len(login.ExtraDNSLabels) > 0 {
			return status.Errorf(status.PreconditionFailed, "couldn't login peer: setup key doesn't allow extra DNS labels")
		}

		if shouldStorePeer {
			if err = transaction.SavePeer(ctx, accountID, peer); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, nil, false, err
	}

	// This is needed to keep in memory for the peer config. Otherwise browser client will end in a retry loop
	peer.Meta = login.Meta

	peerGroupIDs, err = getPeerGroupIDs(ctx, am.Store, accountID, peer.ID)
	if err != nil {
		return nil, nil, nil, false, err
	}

	isRequiresApproval, _, err := am.integratedPeerValidator.IsNotValidPeer(ctx, accountID, peer, peerGroupIDs, settings.Extra)
	if err != nil {
		return nil, nil, nil, false, err
	}

	network, postureChecks, enableSSH, err := getPeerLoginInfo(ctx, am.Store, accountID, peer, !isRequiresApproval)
	if err != nil {
		return nil, nil, nil, false, err
	}

	if shouldUpdatePeers {
		changedPeerIDs := []string{peer.ID}
		affectedPeerIDs := am.resolveAffectedPeersForPeerChanges(ctx, am.Store, accountID, changedPeerIDs)
		if err = am.networkMapController.OnPeersUpdated(ctx, accountID, changedPeerIDs, affectedPeerIDs); err != nil {
			return nil, nil, nil, false, fmt.Errorf("notify network map controller of peer update: %w", err)
		}
	}

	return peer, network, postureChecks, enableSSH, nil
}

// ExtendPeerSession refreshes the peer's SSO session deadline by updating
// LastLogin after a successful JWT validation. The tunnel is untouched: no
// network map sync, no peer reconnect.
//
// Preconditions enforced here:
//   - userID must be present (caller validated the JWT and extracted the user ID).
//   - The peer must exist and be SSO-registered (AddedWithSSOLogin) with
//     LoginExpirationEnabled.
//   - Account-level PeerLoginExpirationEnabled must be true.
//   - The JWT user must match peer.UserID (mirrors LoginPeer at peer.go ~1028).
//
// Returns the new absolute UTC deadline.
func (am *DefaultAccountManager) ExtendPeerSession(ctx context.Context, peerPubKey, userID string) (time.Time, error) {
	if userID == "" {
		return time.Time{}, status.Errorf(status.PermissionDenied, "session extend requires a JWT")
	}

	accountID, err := am.Store.GetAccountIDByPeerPubKey(ctx, peerPubKey)
	if err != nil {
		return time.Time{}, err
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return time.Time{}, err
	}
	if !settings.PeerLoginExpirationEnabled {
		return time.Time{}, status.Errorf(status.PreconditionFailed, "peer login expiration is disabled for the account")
	}

	var refreshed *nbpeer.Peer
	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		peer, err := transaction.GetPeerByPeerPubKey(ctx, store.LockingStrengthUpdate, peerPubKey)
		if err != nil {
			return err
		}

		if !peer.AddedWithSSOLogin() || !peer.LoginExpirationEnabled {
			return status.Errorf(status.PreconditionFailed, "peer is not eligible for session extension")
		}

		if peer.UserID != userID {
			log.WithContext(ctx).Warnf("user mismatch when extending session for peer %s: peer user %s, jwt user %s", peer.ID, peer.UserID, userID)
			return status.NewPeerLoginMismatchError()
		}

		peer = peer.UpdateLastLogin()
		if err := transaction.SavePeer(ctx, accountID, peer); err != nil {
			return err
		}

		if err := transaction.SaveUserLastLogin(ctx, accountID, userID, peer.GetLastLogin()); err != nil {
			log.WithContext(ctx).Debugf("failed to update user last login during session extend: %v", err)
		}

		am.StoreEvent(ctx, userID, peer.ID, accountID, activity.UserExtendedPeerSession, peer.EventMeta(am.networkMapController.GetDNSDomain(settings)))
		refreshed = peer
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}

	// Reschedule the per-account expiration job. schedulePeerLoginExpiration
	// is a no-op when a job is already running, but the running job will pick
	// up the new LastLogin on its next tick. Calling it here is harmless and
	// guarantees a job is in flight even if a prior one ended right before
	// the extend.
	am.schedulePeerLoginExpiration(ctx, accountID)

	return refreshed.SessionExpiresAt(settings.PeerLoginExpirationEnabled, settings.PeerLoginExpiration), nil
}

// getPeerLoginInfo computes the login/register response data (network, posture
// checks, SSH) from the store without building the peer's full network map.
func getPeerLoginInfo(ctx context.Context, transaction store.Store, accountID string, peer *nbpeer.Peer, isValid bool) (*types.Network, []*posture.Checks, bool, error) {
	network, err := transaction.GetAccountNetwork(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, false, fmt.Errorf("get account network: %w", err)
	}

	if !isValid {
		return network, nil, false, nil
	}

	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, false, err
	}

	peerGroupIDs, err := transaction.GetPeerGroupIDs(ctx, store.LockingStrengthNone, accountID, peer.ID)
	if err != nil {
		return nil, nil, false, err
	}

	postureChecks, err := getPeerPostureChecks(ctx, transaction, accountID, peerGroupIDs, policies)
	if err != nil {
		return nil, nil, false, err
	}

	enableSSH, err := isPeerSSHEnabled(ctx, peer, policies, peerGroupIDs)
	if err != nil {
		return nil, nil, false, err
	}

	return network, postureChecks, enableSSH, nil
}

func isPeerSSHEnabled(ctx context.Context, peer *nbpeer.Peer, policies []*types.Policy, peerGroupIDs []string) (bool, error) {
	groupIDsMap := make(map[string]struct{}, len(peerGroupIDs))
	for _, peerID := range peerGroupIDs {
		groupIDsMap[peerID] = struct{}{}
	}
	return types.PeerSSHEnabledFromPolicies(policies, peer.ID, groupIDsMap, peer.SSHEnabled), nil
}

// getPeerPostureChecks returns the posture checks for the peer.
func getPeerPostureChecks(ctx context.Context, transaction store.Store, accountID string, peerGroupIDs []string, policies []*types.Policy) ([]*posture.Checks, error) {
	if len(policies) == 0 {
		return nil, nil
	}

	var peerPostureChecksIDs []string

	for _, policy := range policies {
		if !policy.Enabled || len(policy.SourcePostureChecks) == 0 {
			continue
		}

		postureChecksIDs := processPeerPostureChecks(policy, peerGroupIDs)
		peerPostureChecksIDs = append(peerPostureChecksIDs, postureChecksIDs...)
	}

	peerPostureChecks, err := transaction.GetPostureChecksByIDs(ctx, store.LockingStrengthNone, accountID, peerPostureChecksIDs)
	if err != nil {
		return nil, err
	}

	return maps.Values(peerPostureChecks), nil
}

// processPeerPostureChecks checks if the peer is in the source group of the policy and returns the posture checks.
func processPeerPostureChecks(policy *types.Policy, peerGroupIDs []string) []string {
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		for _, sourceGroup := range rule.Sources {
			if slices.Contains(peerGroupIDs, sourceGroup) {
				return policy.SourcePostureChecks
			}
		}
	}
	return nil
}

// checkIFPeerNeedsLoginWithoutLock checks if the peer needs login without acquiring the account lock. The check validate if the peer was not added via SSO
// and if the peer login is expired.
// The NetBird client doesn't have a way to check if the peer needs login besides sending a login request
// with no JWT token and usually no setup-key. As the client can send up to two login request to check if it is expired
// and before starting the engine, we do the checks without an account lock to avoid piling up requests.
func (am *DefaultAccountManager) checkIFPeerNeedsLoginWithoutLock(ctx context.Context, accountID string, login types.PeerLogin) error {
	peer, err := am.Store.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, login.WireGuardPubKey)
	if err != nil {
		return err
	}

	// if the peer was not added with SSO login we can exit early because peers activated with setup-key
	// doesn't expire, and we avoid extra databases calls.
	if !peer.AddedWithSSOLogin() {
		return nil
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return err
	}

	if peerLoginExpired(ctx, peer, settings) {
		return status.NewPeerLoginExpiredError()
	}

	return nil
}

func (am *DefaultAccountManager) handleExpiredPeer(ctx context.Context, transaction store.Store, user *types.User, peer *nbpeer.Peer) error {
	err := checkAuth(ctx, user.Id, peer)
	if err != nil {
		return err
	}
	// If peer was expired before and if it reached this point, it is re-authenticated.
	// UserID is present, meaning that JWT validation passed successfully in the API layer.
	peer = peer.UpdateLastLogin()
	err = transaction.SavePeer(ctx, peer.AccountID, peer)
	if err != nil {
		return err
	}

	err = transaction.SaveUserLastLogin(ctx, user.AccountID, user.Id, peer.GetLastLogin())
	if err != nil {
		log.WithContext(ctx).Debugf("failed to update user last login: %v", err)
	}

	settings, err := transaction.GetAccountSettings(ctx, store.LockingStrengthNone, peer.AccountID)
	if err != nil {
		return fmt.Errorf("failed to get account settings: %w", err)
	}

	am.StoreEvent(ctx, user.Id, peer.ID, user.AccountID, activity.UserLoggedInPeer, peer.EventMeta(am.networkMapController.GetDNSDomain(settings)))
	return nil
}

func checkIfPeerOwnerIsBlocked(peer *nbpeer.Peer, user *types.User) error {
	if peer.AddedWithSSOLogin() {
		if user.IsBlocked() {
			return status.Errorf(status.PermissionDenied, "user is blocked")
		}
	}
	return nil
}

func checkAuth(ctx context.Context, loginUserID string, peer *nbpeer.Peer) error {
	if loginUserID == "" {
		// absence of a user ID indicates that JWT wasn't provided.
		return status.NewPeerLoginExpiredError()
	}
	if peer.UserID != loginUserID {
		log.WithContext(ctx).Warnf("user mismatch when logging in peer %s: peer user %s, login user %s ", peer.ID, peer.UserID, loginUserID)
		return status.NewPeerLoginMismatchError()
	}
	return nil
}

func peerLoginExpired(ctx context.Context, peer *nbpeer.Peer, settings *types.Settings) bool {
	expired, expiresIn := peer.LoginExpired(settings.PeerLoginExpiration)
	expired = settings.PeerLoginExpirationEnabled && expired
	if expired || peer.Status.LoginExpired {
		log.WithContext(ctx).Debugf("peer's %s login expired %v ago", peer.ID, expiresIn)
		return true
	}
	return false
}

// GetPeer returns a peer visible to the user within an account.
// Users with "peers:read" permission can access any peer. Otherwise, users can access only their own peer.
func (am *DefaultAccountManager) GetPeer(ctx context.Context, accountID, peerID, userID string) (*nbpeer.Peer, error) {
	peer, err := am.Store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		return nil, err
	}

	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if allowed {
		return peer, nil
	}

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return nil, err
	}

	// if admin or user owns this peer, return peer
	if user.IsAdminOrServiceUser() || peer.UserID == userID {
		return peer, nil
	}

	return nil, status.Errorf(status.Internal, "user %s has no access to peer %s under account %s", userID, peer.ID, accountID)
}

// UpdateAccountPeers updates all peers that belong to an account.
// Should be called when changes have to be synced to peers.
func (am *DefaultAccountManager) UpdateAccountPeers(ctx context.Context, accountID string, reason types.UpdateReason) {
	_ = am.networkMapController.UpdateAccountPeers(ctx, accountID, reason)
}

// ExpandAndUpdateAffected expands a Snapshot (loaded INSIDE the now-committed
// transaction) into the affected peers and dispatches the network-map refresh.
// Pure in-memory work plus dispatch, so it runs AFTER commit — the fan-out walk
// never holds the write lock, over the consistent in-tx snapshot. Exported so the
// networks sub-package managers (which hold only account.Manager) share it.
func (am *DefaultAccountManager) ExpandAndUpdateAffected(ctx context.Context, accountID string, snap *affectedpeers.Snapshot, change affectedpeers.Change) {
	go am.dispatchAffected(ctx, accountID, []*affectedpeers.Snapshot{snap}, []affectedpeers.Change{change})
}

// dispatchAffected expands one or more (snapshot, change) pairs — collected across
// one or several transactions — unions their affected peers, and dispatches a
// single network-map refresh. Each snapshot must already be loaded inside its
// transaction; this runs AFTER commit (pure in-memory + dispatch). It is spawned
// in a goroutine that outlives the request, so it detaches from the request
// context's cancellation up front.
func (am *DefaultAccountManager) dispatchAffected(ctx context.Context, accountID string, snaps []*affectedpeers.Snapshot, changes []affectedpeers.Change) {
	ctx = context.WithoutCancel(ctx)

	var lists [][]string
	for i, snap := range snaps {
		if snap == nil {
			continue
		}
		lists = append(lists, snap.Expand(ctx, accountID, changes[i]))
	}

	affectedPeerIDs := unionStrings(lists...)
	if len(affectedPeerIDs) == 0 {
		log.WithContext(ctx).Tracef("no affected peers for account %s", accountID)
		return
	}

	log.WithContext(ctx).Debugf("updating %d affected peers for account %s: %v", len(affectedPeerIDs), accountID, affectedPeerIDs)
	_ = am.networkMapController.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
}

// unionStrings concatenates the given string lists into one deduplicated slice,
// preserving first-occurrence order.
func unionStrings(lists ...[]string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, list := range lists {
		for _, id := range list {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

// affectedPeerIDsFromNetworkMap returns the peer IDs referenced by a peer's
// network map (its connected and offline peers, which include routing and proxy
// peers), excluding the peer itself. For a freshly added peer these are, by ACL
// symmetry, exactly the peers its addition affects.
func affectedPeerIDsFromNetworkMap(nmap *types.NetworkMap, selfPeerID string) []string {
	if nmap == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(nmap.Peers)+len(nmap.OfflinePeers))
	ids := make([]string, 0, len(nmap.Peers)+len(nmap.OfflinePeers))
	add := func(peers []*nbpeer.Peer) {
		for _, p := range peers {
			if p == nil || p.ID == "" || p.ID == selfPeerID {
				continue
			}
			if _, ok := seen[p.ID]; ok {
				continue
			}
			seen[p.ID] = struct{}{}
			ids = append(ids, p.ID)
		}
	}
	add(nmap.Peers)
	add(nmap.OfflinePeers)
	return ids
}

// resolveAffectedPeersForPeerChanges loads a snapshot and expands it for a peer
// change. The graph is unchanged by these paths, so it runs out of the mutating
// transaction (after commit); the resolver derives the peers' group memberships
// during the walk, so the caller passes only the changed peer IDs.
func (am *DefaultAccountManager) resolveAffectedPeersForPeerChanges(ctx context.Context, s store.Store, accountID string, changedPeerIDs []string) []string {
	change := affectedpeers.Change{ChangedPeerIDs: changedPeerIDs}
	snap, err := affectedpeers.Load(ctx, s, accountID, change)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to load snapshot for affected peers: %v", err)
		return nil
	}
	return snap.Expand(ctx, accountID, change)
}

func (am *DefaultAccountManager) BufferUpdateAccountPeers(ctx context.Context, accountID string, reason types.UpdateReason) {
	_ = am.networkMapController.BufferUpdateAccountPeers(ctx, accountID, reason)
}

// UpdateAccountPeer updates a single peer that belongs to an account.
// Should be called when changes need to be synced to a specific peer only.
func (am *DefaultAccountManager) UpdateAccountPeer(ctx context.Context, accountId string, peerId string) {
	_ = am.networkMapController.UpdateAccountPeer(ctx, accountId, peerId)
}

// getNextPeerExpiration returns the minimum duration in which the next peer of the account will expire if it was found.
// If there is no peer that expires this function returns false and a duration of 0.
// This function only considers peers that haven't been expired yet and that are connected.
func (am *DefaultAccountManager) getNextPeerExpiration(ctx context.Context, accountID string) (time.Duration, bool) {
	peersWithExpiry, err := am.Store.GetAccountPeersWithExpiration(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get peers with expiration: %v", err)
		return peerSchedulerRetryInterval, true
	}

	if len(peersWithExpiry) == 0 {
		return 0, false
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account settings: %v", err)
		return peerSchedulerRetryInterval, true
	}

	var nextExpiry *time.Duration
	for _, peer := range peersWithExpiry {
		// consider only connected peers because others will require login on connecting to the management server
		if peer.Status.LoginExpired || !peer.Status.Connected {
			continue
		}
		_, duration := peer.LoginExpired(settings.PeerLoginExpiration)
		if nextExpiry == nil || duration < *nextExpiry {
			// if expiration is below 1s return 1s duration
			// this avoids issues with ticker that can't be set to < 0
			if duration < time.Second {
				return time.Second, true
			}
			nextExpiry = &duration
		}
	}

	if nextExpiry == nil {
		return 0, false
	}

	return *nextExpiry, true
}

// GetNextInactivePeerExpiration returns the minimum duration in which the next peer of the account will expire if it was found.
// If there is no peer that expires this function returns false and a duration of 0.
// This function only considers peers that haven't been expired yet and that are not connected.
func (am *DefaultAccountManager) getNextInactivePeerExpiration(ctx context.Context, accountID string) (time.Duration, bool) {
	peersWithInactivity, err := am.Store.GetAccountPeersWithInactivity(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get peers with inactivity: %v", err)
		return peerSchedulerRetryInterval, true
	}

	if len(peersWithInactivity) == 0 {
		return 0, false
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account settings: %v", err)
		return peerSchedulerRetryInterval, true
	}

	var nextExpiry *time.Duration
	for _, peer := range peersWithInactivity {
		if peer.Status.LoginExpired || peer.Status.Connected {
			continue
		}
		_, duration := peer.SessionExpired(settings.PeerInactivityExpiration)
		if nextExpiry == nil || duration < *nextExpiry {
			// if expiration is below 1s return 1s duration
			// this avoids issues with ticker that can't be set to < 0
			if duration < time.Second {
				return time.Second, true
			}
			nextExpiry = &duration
		}
	}

	if nextExpiry == nil {
		return 0, false
	}

	return *nextExpiry, true
}

// getExpiredPeers returns peers that have been expired.
func (am *DefaultAccountManager) getExpiredPeers(ctx context.Context, accountID string) ([]*nbpeer.Peer, error) {
	peersWithExpiry, err := am.Store.GetAccountPeersWithExpiration(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	var peers []*nbpeer.Peer
	for _, peer := range peersWithExpiry {
		if peer.Status.LoginExpired {
			continue
		}

		expired, _ := peer.LoginExpired(settings.PeerLoginExpiration)
		if expired {
			peers = append(peers, peer)
		}
	}

	return peers, nil
}

// getInactivePeers returns peers that have been expired by inactivity
func (am *DefaultAccountManager) getInactivePeers(ctx context.Context, accountID string) ([]*nbpeer.Peer, error) {
	peersWithInactivity, err := am.Store.GetAccountPeersWithInactivity(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	var peers []*nbpeer.Peer
	for _, inactivePeer := range peersWithInactivity {
		inactive, _ := inactivePeer.SessionExpired(settings.PeerInactivityExpiration)
		if inactive {
			peers = append(peers, inactivePeer)
		}
	}

	return peers, nil
}

// GetPeerGroups returns groups that the peer is part of.
func (am *DefaultAccountManager) GetPeerGroups(ctx context.Context, accountID, peerID string) ([]*types.Group, error) {
	return am.Store.GetPeerGroups(ctx, store.LockingStrengthNone, accountID, peerID)
}

// getPeerGroupIDs returns the IDs of the groups that the peer is part of.
func getPeerGroupIDs(ctx context.Context, transaction store.Store, accountID string, peerID string) ([]string, error) {
	return transaction.GetPeerGroupIDs(ctx, store.LockingStrengthNone, accountID, peerID)
}

// deletePeers deletes all specified peers and sends updates to the remote peers.
// Returns a slice of functions to save events after successful peer deletion.
func deletePeers(ctx context.Context, am *DefaultAccountManager, transaction store.Store, accountID, userID string, peers []*nbpeer.Peer, settings *types.Settings) ([]func(), error) {
	var peerDeletedEvents []func()

	dnsDomain := am.networkMapController.GetDNSDomain(settings)

	for _, peer := range peers {
		if err := transaction.RemovePeerFromAllGroups(ctx, peer.ID); err != nil {
			return nil, fmt.Errorf("failed to remove peer %s from groups", peer.ID)
		}

		peerPolicyRules, err := transaction.GetPolicyRulesByResourceID(ctx, store.LockingStrengthNone, accountID, peer.ID)
		if err != nil {
			return nil, err
		}
		for _, rule := range peerPolicyRules {
			policy, err := transaction.GetPolicyByID(ctx, store.LockingStrengthNone, accountID, rule.PolicyID)
			if err != nil {
				return nil, err
			}

			err = transaction.DeletePolicy(ctx, accountID, rule.PolicyID)
			if err != nil {
				return nil, err
			}

			peerDeletedEvents = append(peerDeletedEvents, func() {
				am.StoreEvent(ctx, userID, peer.ID, accountID, activity.PolicyRemoved, policy.EventMeta())
			})
		}

		if err = transaction.DeletePeer(ctx, accountID, peer.ID); err != nil {
			return nil, err
		}
		if !(peer.ProxyMeta.Embedded || peer.Meta.KernelVersion == "wasm") {
			peerDeletedEvents = append(peerDeletedEvents, func() {
				am.StoreEvent(ctx, userID, peer.ID, accountID, activity.PeerRemovedByUser, peer.EventMeta(dnsDomain))
			})
		}
	}

	return peerDeletedEvents, nil
}

// validatePeerDelete checks if the peer can be deleted.
func (am *DefaultAccountManager) validatePeerDelete(ctx context.Context, transaction store.Store, accountId, peerId string) error {
	linkedInIngressPorts, err := am.proxyController.IsPeerInIngressPorts(ctx, accountId, peerId)
	if err != nil {
		return err
	}

	if linkedInIngressPorts {
		return status.Errorf(status.PreconditionFailed, "peer is linked to ingress ports: %s", peerId)
	}

	linked, router := isPeerLinkedToNetworkRouter(ctx, transaction, accountId, peerId)
	if linked {
		return status.Errorf(status.PreconditionFailed, "peer is linked to a network router: %s", router.ID)
	}

	return nil
}

// isPeerLinkedToNetworkRouter checks if a peer is linked to any network router in the account.
func isPeerLinkedToNetworkRouter(ctx context.Context, transaction store.Store, accountID string, peerID string) (bool, *routerTypes.NetworkRouter) {
	routers, err := transaction.GetNetworkRoutersByAccountID(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving network routers while checking peer linkage: %v", err)
		return false, nil
	}

	for _, router := range routers {
		if router.Peer == peerID {
			return true, router
		}
	}

	return false, nil
}
