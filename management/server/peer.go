package server

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/idp"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/shared/management/domain"

	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"

	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/status"
)

const remoteJobsMinVer = "0.64.0"

// GetPeers returns a list of peers under the given account filtering out peers that do not belong to a user if
// the current user is not an admin.
func (am *DefaultAccountManager) GetPeers(ctx context.Context, accountID, userID, nameFilter, ipFilter string) ([]*nbpeer.Peer, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return nil, err
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}

	accountPeers, err := am.Store.GetAccountPeers(ctx, store.LockingStrengthNone, accountID, nameFilter, ipFilter)
	if err != nil {
		return nil, err
	}

	// @note if the user has permission to read peers it shows all account peers
	if allowed {
		return accountPeers, nil
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get account settings: %w", err)
	}

	if user.IsRestrictable() && settings.RegularUsersViewBlocked {
		return []*nbpeer.Peer{}, nil
	}

	// @note if it does not have permission read peers then only display it's own peers
	peers := make([]*nbpeer.Peer, 0)
	peersMap := make(map[string]*nbpeer.Peer)

	for _, peer := range accountPeers {
		if user.Id != peer.UserID {
			continue
		}
		peers = append(peers, peer)
		peersMap[peer.ID] = peer
	}

	return am.getUserAccessiblePeers(ctx, accountID, peersMap, peers)
}

func (am *DefaultAccountManager) getUserAccessiblePeers(ctx context.Context, accountID string, peersMap map[string]*nbpeer.Peer, peers []*nbpeer.Peer) ([]*nbpeer.Peer, error) {
	account, err := am.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		return nil, err
	}

	approvedPeersMap, err := am.integratedPeerValidator.GetValidatedPeers(ctx, accountID, maps.Values(account.Groups), maps.Values(account.Peers), account.Settings.Extra)
	if err != nil {
		return nil, err
	}

	// fetch all the peers that have access to the user's peers
	for _, peer := range peers {
		aclPeers, _, _, _ := account.GetPeerConnectionResources(ctx, peer, approvedPeersMap, account.GetActiveGroupUsers())
		for _, p := range aclPeers {
			peersMap[p.ID] = p
		}
	}

	return maps.Values(peersMap), nil
}

// MarkPeerConnected marks peer as connected (true) or disconnected (false)
func (am *DefaultAccountManager) MarkPeerConnected(ctx context.Context, peerPubKey string, connected bool, realIP net.IP, accountID string) error {
	var peer *nbpeer.Peer
	var settings *types.Settings
	var expired bool
	var err error

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		peer, err = transaction.GetPeerByPeerPubKey(ctx, store.LockingStrengthUpdate, peerPubKey)
		if err != nil {
			return err
		}

		expired, err = updatePeerStatusAndLocation(ctx, am.geo, transaction, peer, connected, realIP, accountID)
		return err
	})
	if err != nil {
		return err
	}

	if peer.AddedWithSSOLogin() {
		settings, err = am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			return err
		}

		if peer.LoginExpirationEnabled && settings.PeerLoginExpirationEnabled {
			am.schedulePeerLoginExpiration(ctx, accountID)
		}

		if peer.InactivityExpirationEnabled && settings.PeerInactivityExpirationEnabled {
			am.checkAndSchedulePeerInactivityExpiration(ctx, accountID)
		}
	}

	if expired {
		err = am.networkMapController.OnPeersUpdated(ctx, accountID, []string{peer.ID})
		if err != nil {
			return fmt.Errorf("notify network map controller of peer update: %w", err)
		}
	}

	return nil
}

func updatePeerStatusAndLocation(ctx context.Context, geo geolocation.Geolocation, transaction store.Store, peer *nbpeer.Peer, connected bool, realIP net.IP, accountID string) (bool, error) {
	oldStatus := peer.Status.Copy()
	newStatus := oldStatus
	newStatus.LastSeen = time.Now().UTC()
	newStatus.Connected = connected
	// whenever peer got connected that means that it logged in successfully
	if newStatus.Connected {
		newStatus.LoginExpired = false
	}
	peer.Status = newStatus

	if geo != nil && realIP != nil {
		location, err := geo.Lookup(realIP)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to get location for peer %s realip: [%s]: %v", peer.ID, realIP.String(), err)
		} else {
			peer.Location.ConnectionIP = realIP
			peer.Location.CountryCode = location.Country.ISOCode
			peer.Location.CityName = location.City.Names.En
			peer.Location.GeoNameID = location.City.GeonameID
			err = transaction.SavePeerLocation(ctx, accountID, peer)
			if err != nil {
				log.WithContext(ctx).Warnf("could not store location for peer %s: %s", peer.ID, err)
			}
		}
	}

	log.WithContext(ctx).Debugf("saving peer status for peer %s is connected: %t", peer.ID, connected)

	err := transaction.SavePeerStatus(ctx, accountID, peer.ID, *newStatus)
	if err != nil {
		return false, err
	}

	return oldStatus.LoginExpired, nil
}

// UpdatePeer updates peer. Only Peer.Name, Peer.SSHEnabled, Peer.LoginExpirationEnabled and Peer.InactivityExpirationEnabled can be updated.
func (am *DefaultAccountManager) UpdatePeer(ctx context.Context, accountID, userID string, update *nbpeer.Peer) (*nbpeer.Peer, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Update)
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
				_, err := transaction.GetPeerIdByLabel(ctx, store.LockingStrengthNone, accountID, update.Name)
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

	err = am.networkMapController.OnPeersUpdated(ctx, accountID, []string{peer.ID})
	if err != nil {
		return nil, fmt.Errorf("notify network map controller of peer update: %w", err)
	}

	return peer, nil
}

func (am *DefaultAccountManager) CreatePeerJob(ctx context.Context, accountID, peerID, userID string, job *types.Job) error {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.RemoteJobs, operations.Create)
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
	if !strings.Contains(p.Meta.WtVersion, "dev") && (!meetMinVer || err != nil) {
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
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.RemoteJobs, operations.Read)
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
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.RemoteJobs, operations.Read)
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
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Delete)
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

	var peer *nbpeer.Peer
	var settings *types.Settings
	var eventsToStore []func()

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		peer, err = transaction.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
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

		eventsToStore, err = deletePeers(ctx, am, transaction, accountID, userID, []*nbpeer.Peer{peer}, settings)
		if err != nil {
			return fmt.Errorf("failed to delete peer: %w", err)
		}

		if err = transaction.IncrementNetworkSerial(ctx, accountID); err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	if err = am.integratedPeerValidator.PeerDeleted(ctx, accountID, peerID, settings.Extra); err != nil {
		log.WithContext(ctx).Errorf("failed to delete peer %s from integrated validator: %v", peerID, err)
	}

	if err = am.networkMapController.OnPeersDeleted(ctx, accountID, []string{peerID}); err != nil {
		log.WithContext(ctx).Errorf("failed to delete peer %s from network map: %v", peerID, err)
	}

	return nil
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

// AddPeer adds a new peer to the Store.
// Each Account has a list of pre-authorized SetupKey and if no Account has a given key err with a code status.PermissionDenied
// will be returned, meaning the setup key is invalid or not found.
// If a User ID is provided, it means that we passed the authentication using JWT, then we look for account by User ID and register the peer
// to it. We also add the User ID to the peer metadata to identify registrant. If no userID provided, then fail with status.PermissionDenied
// Each new Peer will be assigned a new next net.IP from the Account.Network and Account.Network.LastIP will be updated (IP's are not reused).
// The peer property is just a placeholder for the Peer properties to pass further
func (am *DefaultAccountManager) AddPeer(ctx context.Context, accountID, setupKey, userID string, peer *nbpeer.Peer, temporary bool) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error) {
	if setupKey == "" && userID == "" {
		// no auth method provided => reject access
		return nil, nil, nil, status.Errorf(status.Unauthenticated, "no peer auth method provided, please use a setup key or interactive SSO login")
	}

	upperKey := strings.ToUpper(setupKey)
	hashedKey := sha256.Sum256([]byte(upperKey))
	encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])
	addedByUser := len(userID) > 0

	// This is a handling for the case when the same machine (with the same WireGuard pub key) tries to register twice.
	// Such case is possible when AddPeer function takes long time to finish after AcquireWriteLockByUID (e.g., database is slow)
	// and the peer disconnects with a timeout and tries to register again.
	// We just check if this machine has been registered before and reject the second registration.
	// The connecting peer should be able to recover with a retry.
	_, err := am.Store.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peer.Key)
	if err == nil {
		return nil, nil, nil, status.Errorf(status.PreconditionFailed, "peer has been already registered")
	}

	opEvent := &activity.Event{
		Timestamp: time.Now().UTC(),
	}

	var newPeer *nbpeer.Peer

	var setupKeyID string
	var setupKeyName string
	var ephemeral bool
	var groupsToAdd []string
	var allowExtraDNSLabels bool
	if addedByUser {
		user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
		if err != nil {
			return nil, nil, nil, status.Errorf(status.NotFound, "failed adding new peer: user not found")
		}
		if user.PendingApproval {
			return nil, nil, nil, status.Errorf(status.PermissionDenied, "user pending approval cannot add peers")
		}
		if temporary {
			allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Create)
			if err != nil {
				return nil, nil, nil, status.NewPermissionValidationError(err)
			}

			if !allowed {
				return nil, nil, nil, status.NewPermissionDeniedError()
			}
		} else {
			accountID = user.AccountID
			groupsToAdd = user.AutoGroups
		}
		opEvent.InitiatorID = userID
		opEvent.Activity = activity.PeerAddedByUser
	} else {
		// Validate the setup key
		sk, err := am.Store.GetSetupKeyBySecret(ctx, store.LockingStrengthNone, encodedHashedKey)
		if err != nil {
			return nil, nil, nil, status.Errorf(status.NotFound, "couldn't add peer: setup key is invalid")
		}

		// we will check key twice for early return
		if !sk.IsValid() {
			return nil, nil, nil, status.Errorf(status.NotFound, "couldn't add peer: setup key is invalid")
		}

		opEvent.InitiatorID = sk.Id
		opEvent.Activity = activity.PeerAddedWithSetupKey
		groupsToAdd = sk.AutoGroups
		ephemeral = sk.Ephemeral
		setupKeyID = sk.Id
		setupKeyName = sk.Name
		allowExtraDNSLabels = sk.AllowExtraDNSLabels
		accountID = sk.AccountID
		if !sk.AllowExtraDNSLabels && len(peer.ExtraDNSLabels) > 0 {
			return nil, nil, nil, status.Errorf(status.PreconditionFailed, "couldn't add peer: setup key doesn't allow extra DNS labels")
		}
	}
	opEvent.AccountID = accountID

	if temporary {
		ephemeral = true
	}

	if (strings.ToLower(peer.Meta.Hostname) == "iphone" || strings.ToLower(peer.Meta.Hostname) == "ipad") && userID != "" {
		if am.idpManager != nil {
			userdata, err := am.idpManager.GetUserDataByID(ctx, userID, idp.AppMetadata{WTAccountID: accountID})
			if err == nil && userdata != nil {
				peer.Meta.Hostname = fmt.Sprintf("%s-%s", peer.Meta.Hostname, strings.Split(userdata.Email, "@")[0])
			}
		}
	}

	if err := domain.ValidateDomainsList(peer.ExtraDNSLabels); err != nil {
		return nil, nil, nil, status.Errorf(status.InvalidArgument, "invalid extra DNS labels: %v", err)
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
		Location:                    peer.Location,
		InactivityExpirationEnabled: addedByUser && !temporary,
		ExtraDNSLabels:              peer.ExtraDNSLabels,
		AllowExtraDNSLabels:         allowExtraDNSLabels,
	}
	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get account settings: %w", err)
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

	newPeer = am.integratedPeerValidator.PreparePeer(ctx, accountID, newPeer, groupsToAdd, settings.Extra, temporary)

	network, err := am.Store.GetAccountNetwork(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed getting network: %w", err)
	}

	maxAttempts := 10
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var freeIP net.IP
		freeIP, err = types.AllocateRandomPeerIP(network.Net)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get free IP: %w", err)
		}

		var freeLabel string
		if ephemeral || attempt > 1 {
			freeLabel, err = getPeerIPDNSLabel(freeIP, peer.Meta.Hostname)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to get free DNS label: %w", err)
			}
		} else {
			freeLabel, err = nbdns.GetParsedDomainLabel(peer.Meta.Hostname)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to get free DNS label: %w", err)
			}
		}
		newPeer.DNSLabel = freeLabel
		newPeer.IP = freeIP

		err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
			err = transaction.AddPeerToAccount(ctx, newPeer)
			if err != nil {
				return err
			}

			if len(groupsToAdd) > 0 {
				for _, g := range groupsToAdd {
					err = transaction.AddPeerToGroup(ctx, newPeer.AccountID, newPeer.ID, g)
					if err != nil {
						return err
					}
				}
			}

			err = transaction.AddPeerToAllGroup(ctx, accountID, newPeer.ID)
			if err != nil {
				return fmt.Errorf("failed adding peer to All group: %w", err)
			}

			if addedByUser {
				err := transaction.SaveUserLastLogin(ctx, accountID, userID, newPeer.GetLastLogin())
				if err != nil {
					log.WithContext(ctx).Debugf("failed to update user last login: %v", err)
				}
			} else {
				sk, err := transaction.GetSetupKeyBySecret(ctx, store.LockingStrengthUpdate, encodedHashedKey)
				if err != nil {
					return fmt.Errorf("failed to get setup key: %w", err)
				}

				// we validate at the end to not block the setup key for too long
				if !sk.IsValid() {
					return status.Errorf(status.PreconditionFailed, "couldn't add peer: setup key is invalid")
				}

				err = transaction.IncrementSetupKeyUsage(ctx, setupKeyID)
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

		return nil, nil, nil, fmt.Errorf("failed to add peer to database: %w", err)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to add peer to database after %d attempts: %w", maxAttempts, err)
	}

	if newPeer == nil {
		return nil, nil, nil, fmt.Errorf("new peer is nil")
	}

	opEvent.TargetID = newPeer.ID
	opEvent.Meta = newPeer.EventMeta(am.networkMapController.GetDNSDomain(settings))
	if !addedByUser {
		opEvent.Meta["setup_key_name"] = setupKeyName
	}

	am.StoreEvent(ctx, opEvent.InitiatorID, opEvent.TargetID, opEvent.AccountID, opEvent.Activity, opEvent.Meta)

	if err := am.networkMapController.OnPeersAdded(ctx, accountID, []string{newPeer.ID}); err != nil {
		log.WithContext(ctx).Errorf("failed to update network map cache for peer %s: %v", newPeer.ID, err)
	}

	p, nmap, pc, _, err := am.networkMapController.GetValidatedPeerWithMap(ctx, false, accountID, newPeer)
	return p, nmap, pc, err
}

func getPeerIPDNSLabel(ip net.IP, peerHostName string) (string, error) {
	ip = ip.To4()

	dnsName, err := nbdns.GetParsedDomainLabel(peerHostName)
	if err != nil {
		return "", fmt.Errorf("failed to parse peer host name %s: %w", peerHostName, err)
	}

	return fmt.Sprintf("%s-%d-%d", dnsName, ip[2], ip[3]), nil
}

// SyncPeer checks whether peer is eligible for receiving NetworkMap (authenticated) and returns its NetworkMap if eligible
func (am *DefaultAccountManager) SyncPeer(ctx context.Context, sync types.PeerSync, accountID string) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, int64, error) {
	var peer *nbpeer.Peer
	var updated, versionChanged bool
	var err error
	var postureChecks []*posture.Checks
	var peerGroupIDs []string

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

		peerGroupIDs, err = getPeerGroupIDs(ctx, transaction, accountID, peer.ID)
		if err != nil {
			return err
		}

		updated, versionChanged = peer.UpdateMetaIfNew(sync.Meta)
		if updated {
			am.metrics.AccountManagerMetrics().CountPeerMetUpdate()
			log.WithContext(ctx).Tracef("peer %s metadata updated", peer.ID)
			if err = transaction.SavePeer(ctx, accountID, peer); err != nil {
				return err
			}

			postureChecks, err = getPeerPostureChecks(ctx, transaction, accountID, peer.ID)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, 0, err
	}

	peerNotValid, isStatusChanged, err := am.integratedPeerValidator.IsNotValidPeer(ctx, accountID, peer, peerGroupIDs, settings.Extra)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	if isStatusChanged || sync.UpdateAccountPeers || (updated && (len(postureChecks) > 0 || versionChanged)) {
		err = am.networkMapController.OnPeersUpdated(ctx, accountID, []string{peer.ID})
		if err != nil {
			return nil, nil, nil, 0, fmt.Errorf("notify network map controller of peer update: %w", err)
		}
	}

	return am.networkMapController.GetValidatedPeerWithMap(ctx, peerNotValid, accountID, peer)
}

func (am *DefaultAccountManager) handlePeerLoginNotFound(ctx context.Context, login types.PeerLogin, err error) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error) {
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
	return nil, nil, nil, status.Errorf(status.Internal, "failed while logging in peer")
}

// LoginPeer logs in or registers a peer.
// If peer doesn't exist the function checks whether a setup key or a user is present and registers a new peer if so.
func (am *DefaultAccountManager) LoginPeer(ctx context.Context, login types.PeerLogin) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error) {
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
			return nil, nil, nil, err
		}
	}

	var peer *nbpeer.Peer
	var updateRemotePeers bool
	var isPeerUpdated bool
	var postureChecks []*posture.Checks
	var peerGroupIDs []string

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, nil, err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		peer, err = transaction.GetPeerByPeerPubKey(ctx, store.LockingStrengthUpdate, login.WireGuardPubKey)
		if err != nil {
			return err
		}

		// this flag prevents unnecessary calls to the persistent store.
		shouldStorePeer := false

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
				updateRemotePeers = true
			}
		}

		peerGroupIDs, err = getPeerGroupIDs(ctx, transaction, accountID, peer.ID)
		if err != nil {
			return err
		}

		isPeerUpdated, _ = peer.UpdateMetaIfNew(login.Meta)
		if isPeerUpdated {
			am.metrics.AccountManagerMetrics().CountPeerMetUpdate()
			shouldStorePeer = true

			postureChecks, err = getPeerPostureChecks(ctx, transaction, accountID, peer.ID)
			if err != nil {
				return err
			}
		}

		if peer.SSHKey != login.SSHKey {
			peer.SSHKey = login.SSHKey
			shouldStorePeer = true
			updateRemotePeers = true
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
		return nil, nil, nil, err
	}

	isRequiresApproval, isStatusChanged, err := am.integratedPeerValidator.IsNotValidPeer(ctx, accountID, peer, peerGroupIDs, settings.Extra)
	if err != nil {
		return nil, nil, nil, err
	}

	if updateRemotePeers || isStatusChanged || (isPeerUpdated && len(postureChecks) > 0) {
		err = am.networkMapController.OnPeersUpdated(ctx, accountID, []string{peer.ID})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("notify network map controller of peer update: %w", err)
		}
	}

	p, nmap, pc, _, err := am.networkMapController.GetValidatedPeerWithMap(ctx, isRequiresApproval, accountID, peer)
	return p, nmap, pc, err
}

// getPeerPostureChecks returns the posture checks for the peer.
func getPeerPostureChecks(ctx context.Context, transaction store.Store, accountID, peerID string) ([]*posture.Checks, error) {
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	if len(policies) == 0 {
		return nil, nil
	}

	var peerPostureChecksIDs []string

	for _, policy := range policies {
		if !policy.Enabled || len(policy.SourcePostureChecks) == 0 {
			continue
		}

		postureChecksIDs, err := processPeerPostureChecks(ctx, transaction, policy, accountID, peerID)
		if err != nil {
			return nil, err
		}

		peerPostureChecksIDs = append(peerPostureChecksIDs, postureChecksIDs...)
	}

	peerPostureChecks, err := transaction.GetPostureChecksByIDs(ctx, store.LockingStrengthNone, accountID, peerPostureChecksIDs)
	if err != nil {
		return nil, err
	}

	return maps.Values(peerPostureChecks), nil
}

// processPeerPostureChecks checks if the peer is in the source group of the policy and returns the posture checks.
func processPeerPostureChecks(ctx context.Context, transaction store.Store, policy *types.Policy, accountID, peerID string) ([]string, error) {
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		sourceGroups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, rule.Sources)
		if err != nil {
			return nil, err
		}

		for _, sourceGroup := range rule.Sources {
			group, ok := sourceGroups[sourceGroup]
			if !ok {
				return nil, fmt.Errorf("failed to check peer in policy source group")
			}

			if slices.Contains(group.Peers, peerID) {
				return policy.SourcePostureChecks, nil
			}
		}
	}
	return nil, nil
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

// GetPeer for a given accountID, peerID and userID error if not found.
func (am *DefaultAccountManager) GetPeer(ctx context.Context, accountID, peerID, userID string) (*nbpeer.Peer, error) {
	peer, err := am.Store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		return nil, err
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Read)
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

	return am.checkIfUserOwnsPeer(ctx, accountID, userID, peer)
}

func (am *DefaultAccountManager) checkIfUserOwnsPeer(ctx context.Context, accountID, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, error) {
	account, err := am.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		return nil, err
	}

	approvedPeersMap, err := am.integratedPeerValidator.GetValidatedPeers(ctx, accountID, maps.Values(account.Groups), maps.Values(account.Peers), account.Settings.Extra)
	if err != nil {
		return nil, err
	}

	// it is also possible that user doesn't own the peer but some of his peers have access to it,
	// this is a valid case, show the peer as well.
	userPeers, err := am.Store.GetUserPeers(ctx, store.LockingStrengthNone, accountID, userID)
	if err != nil {
		return nil, err
	}

	for _, p := range userPeers {
		aclPeers, _, _, _ := account.GetPeerConnectionResources(ctx, p, approvedPeersMap, account.GetActiveGroupUsers())
		for _, aclPeer := range aclPeers {
			if aclPeer.ID == peer.ID {
				return peer, nil
			}
		}
	}

	return nil, status.Errorf(status.Internal, "user %s has no access to peer %s under account %s", userID, peer.ID, accountID)
}

// UpdateAccountPeers updates all peers that belong to an account.
// Should be called when changes have to be synced to peers.
func (am *DefaultAccountManager) UpdateAccountPeers(ctx context.Context, accountID string) {
	_ = am.networkMapController.UpdateAccountPeers(ctx, accountID)
}

func (am *DefaultAccountManager) BufferUpdateAccountPeers(ctx context.Context, accountID string) {
	_ = am.networkMapController.BufferUpdateAccountPeers(ctx, accountID)
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
		peerDeletedEvents = append(peerDeletedEvents, func() {
			am.StoreEvent(ctx, userID, peer.ID, accountID, activity.PeerRemovedByUser, peer.EventMeta(dnsDomain))
		})
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
