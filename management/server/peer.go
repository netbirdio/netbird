package server

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/posture"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
)

// PeerSync used as a data object between the gRPC API and AccountManager on Sync request.
type PeerSync struct {
	// WireGuardPubKey is a peers WireGuard public key
	WireGuardPubKey string
	// Meta is the system information passed by peer, must be always present
	Meta nbpeer.PeerSystemMeta
	// UpdateAccountPeers indicate updating account peers,
	// which occurs when the peer's metadata is updated
	UpdateAccountPeers bool
}

// PeerLogin used as a data object between the gRPC API and AccountManager on Login request.
type PeerLogin struct {
	// WireGuardPubKey is a peers WireGuard public key
	WireGuardPubKey string
	// SSHKey is a peer's ssh key. Can be empty (e.g., old version do not provide it, or this feature is disabled)
	SSHKey string
	// Meta is the system information passed by peer, must be always present.
	Meta nbpeer.PeerSystemMeta
	// UserID indicates that JWT was used to log in, and it was valid. Can be empty when SetupKey is used or auth is not required.
	UserID string
	// SetupKey references to a server.SetupKey to log in. Can be empty when UserID is used or auth is not required.
	SetupKey string
	// ConnectionIP is the real IP of the peer
	ConnectionIP net.IP
}

// ListPeers returns a list of peers under the given account.
func (am *DefaultAccountManager) ListPeers(ctx context.Context, accountID, userID string) ([]*nbpeer.Peer, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	return am.Store.GetAccountPeers(ctx, LockingStrengthShare, accountID)
}

// GetUserPeers returns a list of peers under the given account filtering out peers that do not belong to a user if
// the current user is not an admin.
func (am *DefaultAccountManager) GetUserPeers(ctx context.Context, accountID, userID string) ([]*nbpeer.Peer, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	approvedPeersMap, err := am.GetValidatedPeers(ctx, accountID)
	if err != nil {
		return nil, err
	}
	peers := make([]*nbpeer.Peer, 0)
	peersMap := make(map[string]*nbpeer.Peer)

	if user.IsRegularUser() && settings.RegularUsersViewBlocked {
		return peers, nil
	}

	accountPeers, err := am.Store.GetAccountPeers(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}
	for _, peer := range accountPeers {
		if user.IsRegularUser() && user.Id != peer.UserID {
			// only display peers that belong to the current user if the current user is not an admin
			continue
		}
		p := peer.Copy()
		peers = append(peers, p)
		peersMap[peer.ID] = p
	}

	if user.IsAdminOrServiceUser() {
		return peers, nil
	}

	account, err := am.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf(errGetAccountFmt, err)
	}

	// fetch all the peers that have access to the user's peers
	for _, peer := range peers {
		aclPeers, _ := account.getPeerConnectionResources(ctx, peer.ID, approvedPeersMap)
		for _, p := range aclPeers {
			peersMap[p.ID] = p
		}
	}

	peers = make([]*nbpeer.Peer, 0, len(peersMap))
	for _, peer := range peersMap {
		peers = append(peers, peer)
	}

	return peers, nil
}

// MarkPeerConnected marks peer as connected (true) or disconnected (false)
func (am *DefaultAccountManager) MarkPeerConnected(ctx context.Context, peerPubKey string, connected bool, realIP net.IP, accountID string) error {
	peer, err := am.Store.GetPeerByPeerPubKey(ctx, LockingStrengthShare, peerPubKey)
	if err != nil {
		return err
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return err
	}

	expired, err := am.updatePeerStatusAndLocation(ctx, peer, connected, realIP, accountID)
	if err != nil {
		return err
	}

	if peer.AddedWithSSOLogin() {
		if peer.LoginExpirationEnabled && settings.PeerLoginExpirationEnabled {
			am.checkAndSchedulePeerLoginExpiration(ctx, accountID)
		}

		if peer.InactivityExpirationEnabled && settings.PeerInactivityExpirationEnabled {
			am.checkAndSchedulePeerInactivityExpiration(ctx, accountID)
		}
	}

	if expired {
		// we need to update other peers because when peer login expires all other peers are notified to disconnect from
		// the expired one. Here we notify them that connection is now allowed again.
		am.updateAccountPeers(ctx, accountID)
	}

	return nil
}

func (am *DefaultAccountManager) updatePeerStatusAndLocation(ctx context.Context, peer *nbpeer.Peer, connected bool, realIP net.IP, accountID string) (bool, error) {
	oldStatus := peer.Status.Copy()
	newStatus := oldStatus
	newStatus.LastSeen = time.Now().UTC()
	newStatus.Connected = connected
	// whenever peer got connected that means that it logged in successfully
	if newStatus.Connected {
		newStatus.LoginExpired = false
	}
	peer.Status = newStatus

	if am.geo != nil && realIP != nil {
		location, err := am.geo.Lookup(realIP)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to get location for peer %s realip: [%s]: %v", peer.ID, realIP.String(), err)
		} else {
			peer.Location.ConnectionIP = realIP
			peer.Location.CountryCode = location.Country.ISOCode
			peer.Location.CityName = location.City.Names.En
			peer.Location.GeoNameID = location.City.GeonameID
			err = am.Store.SavePeerLocation(ctx, LockingStrengthUpdate, accountID, peer)
			if err != nil {
				log.WithContext(ctx).Warnf("could not store location for peer %s: %s", peer.ID, err)
			}
		}
	}

	err := am.Store.SavePeerStatus(ctx, LockingStrengthUpdate, accountID, peer.ID, *newStatus)
	if err != nil {
		return false, err
	}

	return oldStatus.LoginExpired, nil
}

// UpdatePeer updates peer. Only Peer.Name, Peer.SSHEnabled, Peer.LoginExpirationEnabled and Peer.InactivityExpirationEnabled can be updated.
func (am *DefaultAccountManager) UpdatePeer(ctx context.Context, accountID, userID string, update *nbpeer.Peer) (*nbpeer.Peer, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	peer, err := am.Store.GetPeerByID(ctx, LockingStrengthShare, accountID, update.ID)
	if err != nil {
		return nil, err
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	peerGroupList, err := am.getPeerGroupIDs(ctx, accountID, update.ID)
	if err != nil {
		return nil, err
	}

	update, err = am.integratedPeerValidator.ValidatePeer(ctx, update, peer, userID, accountID, am.GetDNSDomain(), peerGroupList, settings.Extra)
	if err != nil {
		return nil, err
	}

	var sshChanged, peerLabelChanged, loginExpirationChanged, inactivityExpirationChanged bool

	if peer.SSHEnabled != update.SSHEnabled {
		peer.SSHEnabled = update.SSHEnabled
		sshChanged = true
	}

	if peer.Name != update.Name {
		peer.Name = update.Name
		peerLabelChanged = true

		existingLabels, err := am.getPeerDNSLabels(ctx, accountID)
		if err != nil {
			return nil, err
		}

		newLabel, err := getPeerHostLabel(peer.Name, existingLabels)
		if err != nil {
			return nil, err
		}

		peer.DNSLabel = newLabel
	}

	if peer.LoginExpirationEnabled != update.LoginExpirationEnabled {
		if !peer.AddedWithSSOLogin() {
			return nil, status.Errorf(status.PreconditionFailed, "this peer hasn't been added with the SSO login, therefore the login expiration can't be updated")
		}
		peer.LoginExpirationEnabled = update.LoginExpirationEnabled
		loginExpirationChanged = true
	}

	if peer.InactivityExpirationEnabled != update.InactivityExpirationEnabled {
		if !peer.AddedWithSSOLogin() {
			return nil, status.Errorf(status.PreconditionFailed, "this peer hasn't been added with the SSO login, therefore the inactivity expiration can't be updated")
		}
		peer.InactivityExpirationEnabled = update.InactivityExpirationEnabled
		inactivityExpirationChanged = true
	}

	if err = am.Store.SavePeer(ctx, LockingStrengthUpdate, accountID, peer); err != nil {
		return nil, err
	}

	if sshChanged {
		event := activity.PeerSSHEnabled
		if !peer.SSHEnabled {
			event = activity.PeerSSHDisabled
		}
		am.StoreEvent(ctx, userID, peer.IP.String(), accountID, event, peer.EventMeta(am.GetDNSDomain()))
	}

	if peerLabelChanged {
		am.StoreEvent(ctx, userID, peer.ID, accountID, activity.PeerRenamed, peer.EventMeta(am.GetDNSDomain()))
		am.updateAccountPeers(ctx, accountID)
	}

	if loginExpirationChanged {
		event := activity.PeerLoginExpirationEnabled
		if !peer.LoginExpirationEnabled {
			event = activity.PeerLoginExpirationDisabled
		}
		am.StoreEvent(ctx, userID, peer.IP.String(), accountID, event, peer.EventMeta(am.GetDNSDomain()))

		if peer.AddedWithSSOLogin() && peer.LoginExpirationEnabled && settings.PeerLoginExpirationEnabled {
			am.checkAndSchedulePeerLoginExpiration(ctx, accountID)
		}
	}

	if inactivityExpirationChanged {
		event := activity.PeerInactivityExpirationEnabled
		if !peer.InactivityExpirationEnabled {
			event = activity.PeerInactivityExpirationDisabled
		}
		am.StoreEvent(ctx, userID, peer.IP.String(), accountID, event, peer.EventMeta(am.GetDNSDomain()))

		if peer.AddedWithSSOLogin() && peer.InactivityExpirationEnabled && settings.PeerInactivityExpirationEnabled {
			am.checkAndSchedulePeerInactivityExpiration(ctx, accountID)
		}
	}

	return peer, nil
}

// DeletePeer removes peer from the account by its IP
func (am *DefaultAccountManager) DeletePeer(ctx context.Context, accountID, peerID, userID string) error {
	peerAccountID, err := am.Store.GetAccountIDByPeerID(ctx, LockingStrengthShare, peerID)
	if err != nil {
		return err
	}

	if peerAccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	updateAccountPeers, err := am.isPeerInActiveGroup(ctx, accountID, peerID)
	if err != nil {
		return err
	}

	var peer *nbpeer.Peer
	var addPeerRemovedEvents []func()

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		peer, err = transaction.GetPeerByID(ctx, LockingStrengthShare, accountID, peerID)
		if err != nil {
			return fmt.Errorf("failed to get peer to delete: %w", err)
		}

		addPeerRemovedEvents, err = deletePeers(ctx, am, transaction, accountID, userID, []*nbpeer.Peer{peer})
		if err != nil {
			return fmt.Errorf("failed to delete peer: %w", err)
		}

		return nil
	})

	for _, addPeerRemovedEvent := range addPeerRemovedEvents {
		addPeerRemovedEvent()
	}

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return nil
}

// GetNetworkMap returns Network map for a given peer (omits original peer from the Peers result)
func (am *DefaultAccountManager) GetNetworkMap(ctx context.Context, peerID string) (*NetworkMap, error) {
	account, err := am.Store.GetAccountByPeerID(ctx, peerID)
	if err != nil {
		return nil, err
	}

	peer := account.GetPeer(peerID)
	if peer == nil {
		return nil, status.Errorf(status.NotFound, "peer with ID %s not found", peerID)
	}

	groups := make(map[string][]string)
	for groupID, group := range account.Groups {
		groups[groupID] = group.Peers
	}

	validatedPeers, err := am.integratedPeerValidator.GetValidatedPeers(account.Id, account.Groups, account.Peers, account.Settings.Extra)
	if err != nil {
		return nil, err
	}
	customZone := account.GetPeersCustomZone(ctx, am.dnsDomain)
	return account.GetPeerNetworkMap(ctx, peer.ID, customZone, validatedPeers, nil), nil
}

// GetPeerNetwork returns the Network for a given peer
func (am *DefaultAccountManager) GetPeerNetwork(ctx context.Context, peerID string) (*Network, error) {
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
func (am *DefaultAccountManager) AddPeer(ctx context.Context, setupKey, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, *NetworkMap, []*posture.Checks, error) {
	if setupKey == "" && userID == "" {
		// no auth method provided => reject access
		return nil, nil, nil, status.Errorf(status.Unauthenticated, "no peer auth method provided, please use a setup key or interactive SSO login")
	}

	upperKey := strings.ToUpper(setupKey)
	hashedKey := sha256.Sum256([]byte(upperKey))
	encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])
	var accountID string
	var err error
	addedByUser := false
	if len(userID) > 0 {
		addedByUser = true
		accountID, err = am.Store.GetAccountIDByUserID(ctx, LockingStrengthShare, userID)
	} else {
		accountID, err = am.Store.GetAccountIDBySetupKey(ctx, encodedHashedKey)
	}
	if err != nil {
		return nil, nil, nil, status.Errorf(status.NotFound, "failed adding new peer: account not found")
	}

	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()

	// This is a handling for the case when the same machine (with the same WireGuard pub key) tries to register twice.
	// Such case is possible when AddPeer function takes long time to finish after AcquireWriteLockByUID (e.g., database is slow)
	// and the peer disconnects with a timeout and tries to register again.
	// We just check if this machine has been registered before and reject the second registration.
	// The connecting peer should be able to recover with a retry.
	_, err = am.Store.GetPeerByPeerPubKey(ctx, LockingStrengthShare, peer.Key)
	if err == nil {
		return nil, nil, nil, status.Errorf(status.PreconditionFailed, "peer has been already registered")
	}

	opEvent := &activity.Event{
		Timestamp: time.Now().UTC(),
		AccountID: accountID,
	}

	var newPeer *nbpeer.Peer

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		var setupKeyID string
		var setupKeyName string
		var ephemeral bool
		var groupsToAdd []string
		if addedByUser {
			user, err := transaction.GetUserByUserID(ctx, LockingStrengthUpdate, userID)
			if err != nil {
				return fmt.Errorf("failed to get user groups: %w", err)
			}
			groupsToAdd = user.AutoGroups
			opEvent.InitiatorID = userID
			opEvent.Activity = activity.PeerAddedByUser
		} else {
			// Validate the setup key
			sk, err := transaction.GetSetupKeyBySecret(ctx, LockingStrengthUpdate, encodedHashedKey)
			if err != nil {
				return fmt.Errorf("failed to get setup key: %w", err)
			}

			if !sk.IsValid() {
				return status.Errorf(status.PreconditionFailed, "couldn't add peer: setup key is invalid")
			}

			opEvent.InitiatorID = sk.Id
			opEvent.Activity = activity.PeerAddedWithSetupKey
			groupsToAdd = sk.AutoGroups
			ephemeral = sk.Ephemeral
			setupKeyID = sk.Id
			setupKeyName = sk.Name
		}

		if strings.ToLower(peer.Meta.Hostname) == "iphone" || strings.ToLower(peer.Meta.Hostname) == "ipad" && userID != "" {
			if am.idpManager != nil {
				userdata, err := am.idpManager.GetUserDataByID(ctx, userID, idp.AppMetadata{WTAccountID: accountID})
				if err == nil && userdata != nil {
					peer.Meta.Hostname = fmt.Sprintf("%s-%s", peer.Meta.Hostname, strings.Split(userdata.Email, "@")[0])
				}
			}
		}

		freeLabel, err := am.getFreeDNSLabel(ctx, transaction, accountID, peer.Meta.Hostname)
		if err != nil {
			return fmt.Errorf("failed to get free DNS label: %w", err)
		}

		freeIP, err := am.getFreeIP(ctx, transaction, accountID)
		if err != nil {
			return fmt.Errorf("failed to get free IP: %w", err)
		}

		registrationTime := time.Now().UTC()
		newPeer = &nbpeer.Peer{
			ID:                          xid.New().String(),
			AccountID:                   accountID,
			Key:                         peer.Key,
			IP:                          freeIP,
			Meta:                        peer.Meta,
			Name:                        peer.Meta.Hostname,
			DNSLabel:                    freeLabel,
			UserID:                      userID,
			Status:                      &nbpeer.PeerStatus{Connected: false, LastSeen: registrationTime},
			SSHEnabled:                  false,
			SSHKey:                      peer.SSHKey,
			LastLogin:                   registrationTime,
			CreatedAt:                   registrationTime,
			LoginExpirationEnabled:      addedByUser,
			Ephemeral:                   ephemeral,
			Location:                    peer.Location,
			InactivityExpirationEnabled: addedByUser,
		}
		opEvent.TargetID = newPeer.ID
		opEvent.Meta = newPeer.EventMeta(am.GetDNSDomain())
		if !addedByUser {
			opEvent.Meta["setup_key_name"] = setupKeyName
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

		settings, err := transaction.GetAccountSettings(ctx, LockingStrengthShare, accountID)
		if err != nil {
			return fmt.Errorf("failed to get account settings: %w", err)
		}
		newPeer = am.integratedPeerValidator.PreparePeer(ctx, accountID, newPeer, groupsToAdd, settings.Extra)

		err = transaction.AddPeerToAllGroup(ctx, accountID, newPeer.ID)
		if err != nil {
			return fmt.Errorf("failed adding peer to All group: %w", err)
		}

		if len(groupsToAdd) > 0 {
			for _, g := range groupsToAdd {
				err = transaction.AddPeerToGroup(ctx, accountID, newPeer.ID, g)
				if err != nil {
					return err
				}
			}
		}

		err = transaction.AddPeerToAccount(ctx, newPeer)
		if err != nil {
			return fmt.Errorf("failed to add peer to account: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		if addedByUser {
			err := transaction.SaveUserLastLogin(ctx, accountID, userID, newPeer.LastLogin)
			if err != nil {
				return fmt.Errorf("failed to update user last login: %w", err)
			}
		} else {
			err = transaction.IncrementSetupKeyUsage(ctx, setupKeyID)
			if err != nil {
				return fmt.Errorf("failed to increment setup key usage: %w", err)
			}
		}

		log.WithContext(ctx).Debugf("Peer %s added to account %s", newPeer.ID, accountID)
		return nil
	})

	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to add peer to database: %w", err)
	}

	if newPeer == nil {
		return nil, nil, nil, fmt.Errorf("new peer is nil")
	}

	am.StoreEvent(ctx, opEvent.InitiatorID, opEvent.TargetID, opEvent.AccountID, opEvent.Activity, opEvent.Meta)

	unlock()
	unlock = nil

	updateAccountPeers, err := am.isPeerInActiveGroup(ctx, accountID, newPeer.ID)
	if err != nil {
		return nil, nil, nil, err
	}

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return am.getValidatedPeerWithMap(ctx, false, accountID, newPeer)
}

func (am *DefaultAccountManager) getFreeIP(ctx context.Context, store Store, accountID string) (net.IP, error) {
	takenIps, err := store.GetTakenIPs(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get taken IPs: %w", err)
	}

	network, err := store.GetAccountNetwork(ctx, LockingStrengthUpdate, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed getting network: %w", err)
	}

	nextIp, err := AllocatePeerIP(network.Net, takenIps)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate new peer ip: %w", err)
	}

	return nextIp, nil
}

// SyncPeer checks whether peer is eligible for receiving NetworkMap (authenticated) and returns its NetworkMap if eligible
func (am *DefaultAccountManager) SyncPeer(ctx context.Context, sync PeerSync, accountID string) (*nbpeer.Peer, *NetworkMap, []*posture.Checks, error) {
	peer, err := am.Store.GetPeerByPeerPubKey(ctx, LockingStrengthShare, sync.WireGuardPubKey)
	if err != nil {
		return nil, nil, nil, status.NewPeerNotRegisteredError()
	}

	if peer.UserID != "" {
		user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, peer.UserID)
		if err != nil {
			return nil, nil, nil, err
		}

		err = checkIfPeerOwnerIsBlocked(peer, user)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, nil, nil, err
	}

	if peerLoginExpired(ctx, peer, settings) {
		return nil, nil, nil, status.NewPeerLoginExpiredError()
	}

	peerGroupList, err := am.getPeerGroupIDs(ctx, accountID, peer.ID)
	if err != nil {
		return nil, nil, nil, err
	}

	peerNotValid, isStatusChanged, err := am.integratedPeerValidator.IsNotValidPeer(ctx, accountID, peer, peerGroupList, settings.Extra)
	if err != nil {
		return nil, nil, nil, err
	}

	updated := peer.UpdateMetaIfNew(sync.Meta)
	if updated {
		err = am.Store.SavePeer(ctx, LockingStrengthUpdate, accountID, peer)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	if isStatusChanged || (updated && sync.UpdateAccountPeers) {
		am.updateAccountPeers(ctx, accountID)
	}

	return am.getValidatedPeerWithMap(ctx, peerNotValid, accountID, peer)
}

// LoginPeer logs in or registers a peer.
// If peer doesn't exist the function checks whether a setup key or a user is present and registers a new peer if so.
func (am *DefaultAccountManager) LoginPeer(ctx context.Context, login PeerLogin) (*nbpeer.Peer, *NetworkMap, []*posture.Checks, error) {
	accountID, err := am.Store.GetAccountIDByPeerPubKey(ctx, login.WireGuardPubKey)
	if err != nil {
		if errStatus, ok := status.FromError(err); ok && errStatus.Type() == status.NotFound {
			// we couldn't find this peer by its public key which can mean that peer hasn't been registered yet.
			// Try registering it.
			newPeer := &nbpeer.Peer{
				Key:      login.WireGuardPubKey,
				Meta:     login.Meta,
				SSHKey:   login.SSHKey,
				Location: nbpeer.Location{ConnectionIP: login.ConnectionIP},
			}

			return am.AddPeer(ctx, login.SetupKey, login.UserID, newPeer)
		}

		log.WithContext(ctx).Errorf("failed while logging in peer %s: %v", login.WireGuardPubKey, err)
		return nil, nil, nil, status.Errorf(status.Internal, "failed while logging in peer")
	}

	// when the client sends a login request with a JWT which is used to get the user ID,
	// it means that the client has already checked if it needs login and had been through the SSO flow
	// so, we can skip this check and directly proceed with the login
	if login.UserID == "" {
		log.Info("Peer needs login")
		err = am.checkIFPeerNeedsLoginWithoutLock(ctx, accountID, login)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	unlockAccount := am.Store.AcquireReadLockByUID(ctx, accountID)
	defer unlockAccount()
	unlockPeer := am.Store.AcquireWriteLockByUID(ctx, login.WireGuardPubKey)
	defer func() {
		if unlockPeer != nil {
			unlockPeer()
		}
	}()

	peer, err := am.Store.GetPeerByPeerPubKey(ctx, LockingStrengthUpdate, login.WireGuardPubKey)
	if err != nil {
		return nil, nil, nil, err
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, nil, nil, err
	}

	// this flag prevents unnecessary calls to the persistent store.
	shouldStorePeer := false
	updateRemotePeers := false

	if login.UserID != "" {
		if peer.UserID != login.UserID {
			log.Warnf("user mismatch when logging in peer %s: peer user %s, login user %s ", peer.ID, peer.UserID, login.UserID)
			return nil, nil, nil, status.Errorf(status.Unauthenticated, "invalid user")
		}

		changed, err := am.handleUserPeer(ctx, peer, settings)
		if err != nil {
			return nil, nil, nil, err
		}
		if changed {
			shouldStorePeer = true
			updateRemotePeers = true
		}
	}

	groups, err := am.Store.GetAccountGroups(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, nil, nil, err
	}

	var grps []string
	for _, group := range groups {
		for _, id := range group.Peers {
			if id == peer.ID {
				grps = append(grps, group.ID)
				break
			}
		}
	}

	isRequiresApproval, isStatusChanged, err := am.integratedPeerValidator.IsNotValidPeer(ctx, accountID, peer, grps, settings.Extra)
	if err != nil {
		return nil, nil, nil, err
	}

	updated := peer.UpdateMetaIfNew(login.Meta)
	if updated {
		shouldStorePeer = true
	}

	if peer.SSHKey != login.SSHKey {
		peer.SSHKey = login.SSHKey
		shouldStorePeer = true
	}

	if shouldStorePeer {
		err = am.Store.SavePeer(ctx, LockingStrengthUpdate, accountID, peer)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	unlockPeer()
	unlockPeer = nil

	if updateRemotePeers || isStatusChanged {
		am.updateAccountPeers(ctx, accountID)
	}

	return am.getValidatedPeerWithMap(ctx, isRequiresApproval, accountID, peer)
}

// checkIFPeerNeedsLoginWithoutLock checks if the peer needs login without acquiring the account lock. The check validate if the peer was not added via SSO
// and if the peer login is expired.
// The NetBird client doesn't have a way to check if the peer needs login besides sending a login request
// with no JWT token and usually no setup-key. As the client can send up to two login request to check if it is expired
// and before starting the engine, we do the checks without an account lock to avoid piling up requests.
func (am *DefaultAccountManager) checkIFPeerNeedsLoginWithoutLock(ctx context.Context, accountID string, login PeerLogin) error {
	peer, err := am.Store.GetPeerByPeerPubKey(ctx, LockingStrengthShare, login.WireGuardPubKey)
	if err != nil {
		return err
	}

	// if the peer was not added with SSO login we can exit early because peers activated with setup-key
	// doesn't expire, and we avoid extra databases calls.
	if !peer.AddedWithSSOLogin() {
		return nil
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return err
	}

	if peerLoginExpired(ctx, peer, settings) {
		return status.NewPeerLoginExpiredError()
	}

	return nil
}

func (am *DefaultAccountManager) getValidatedPeerWithMap(ctx context.Context, isRequiresApproval bool, accountID string, peer *nbpeer.Peer) (*nbpeer.Peer, *NetworkMap, []*posture.Checks, error) {
	if isRequiresApproval {
		network, err := am.Store.GetAccountNetwork(ctx, LockingStrengthShare, accountID)
		if err != nil {
			return nil, nil, nil, err
		}

		emptyMap := &NetworkMap{
			Network: network.Copy(),
		}
		return peer, emptyMap, nil, nil
	}

	account, err := am.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		return nil, nil, nil, err
	}

	approvedPeersMap, err := am.GetValidatedPeers(ctx, account.Id)
	if err != nil {
		return nil, nil, nil, err
	}

	postureChecks, err := am.getPeerPostureChecks(ctx, account.Id, peer.ID)
	if err != nil {
		return nil, nil, nil, err
	}

	customZone := account.GetPeersCustomZone(ctx, am.dnsDomain)
	return peer, account.GetPeerNetworkMap(ctx, peer.ID, customZone, approvedPeersMap, am.metrics.AccountManagerMetrics()), postureChecks, nil
}

func (am *DefaultAccountManager) handleExpiredPeer(ctx context.Context, user *User, peer *nbpeer.Peer) error {
	err := checkAuth(ctx, user.Id, peer)
	if err != nil {
		return err
	}
	// If peer was expired before and if it reached this point, it is re-authenticated.
	// UserID is present, meaning that JWT validation passed successfully in the API layer.
	peer = peer.UpdateLastLogin()
	err = am.Store.SavePeer(ctx, LockingStrengthUpdate, peer.AccountID, peer)
	if err != nil {
		return err
	}

	err = am.Store.SaveUserLastLogin(ctx, user.AccountID, user.Id, peer.LastLogin)
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, user.Id, peer.ID, user.AccountID, activity.UserLoggedInPeer, peer.EventMeta(am.GetDNSDomain()))
	return nil
}

func checkIfPeerOwnerIsBlocked(peer *nbpeer.Peer, user *User) error {
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
		return status.Errorf(status.Unauthenticated, "can't login with this credentials")
	}
	return nil
}

func peerLoginExpired(ctx context.Context, peer *nbpeer.Peer, settings *Settings) bool {
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
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	if user.IsRegularUser() && settings.RegularUsersViewBlocked {
		return nil, status.Errorf(status.Internal, "user %s has no access to his own peer %s under account %s", userID, peerID, accountID)
	}

	peer, err := am.Store.GetPeerByID(ctx, LockingStrengthShare, accountID, peerID)
	if err != nil {
		return nil, err
	}

	// if admin or user owns this peer, return peer
	if user.IsAdminOrServiceUser() || peer.UserID == userID {
		return peer, nil
	}

	// it is also possible that user doesn't own the peer but some of his peers have access to it,
	// this is a valid case, show the peer as well.
	userPeers, err := am.Store.GetUserPeers(ctx, LockingStrengthShare, accountID, userID)
	if err != nil {
		return nil, err
	}

	approvedPeersMap, err := am.GetValidatedPeers(ctx, accountID)
	if err != nil {
		return nil, err
	}

	account, err := am.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf(errGetAccountFmt, err)
	}

	for _, p := range userPeers {
		aclPeers, _ := account.getPeerConnectionResources(ctx, p.ID, approvedPeersMap)
		for _, aclPeer := range aclPeers {
			if aclPeer.ID == peerID {
				return peer, nil
			}
		}
	}

	return nil, status.Errorf(status.Internal, "user %s has no access to peer %s under account %s", userID, peerID, accountID)
}

// updateAccountPeers updates all peers that belong to an account.
// Should be called when changes have to be synced to peers.
func (am *DefaultAccountManager) updateAccountPeers(ctx context.Context, accountID string) {
	start := time.Now()
	defer func() {
		if am.metrics != nil {
			am.metrics.AccountManagerMetrics().CountUpdateAccountPeersDuration(time.Since(start))
		}
	}()

	account, err := am.requestBuffer.GetAccountWithBackpressure(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to send out updates to peers. failed to get account: %v", err)
		return
	}

	peers := account.GetPeers()

	approvedPeersMap, err := am.GetValidatedPeers(ctx, account.Id)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to send out updates to peers, failed to validate peer: %v", err)
		return
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	dnsCache := &DNSConfigCache{}
	customZone := account.GetPeersCustomZone(ctx, am.dnsDomain)

	for _, peer := range peers {
		if !am.peersUpdateManager.HasChannel(peer.ID) {
			log.WithContext(ctx).Tracef("peer %s doesn't have a channel, skipping network map update", peer.ID)
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{}
		go func(p *nbpeer.Peer) {
			defer wg.Done()
			defer func() { <-semaphore }()

			postureChecks, err := am.getPeerPostureChecks(ctx, account.Id, p.ID)
			if err != nil {
				log.WithContext(ctx).Debugf("failed to get posture checks for peer %s: %v", peer.ID, err)
				return
			}

			remotePeerNetworkMap := account.GetPeerNetworkMap(ctx, p.ID, customZone, approvedPeersMap, am.metrics.AccountManagerMetrics())
			update := toSyncResponse(ctx, nil, p, nil, nil, remotePeerNetworkMap, am.GetDNSDomain(), postureChecks, dnsCache)
			am.peersUpdateManager.SendUpdate(ctx, p.ID, &UpdateMessage{Update: update, NetworkMap: remotePeerNetworkMap})
		}(peer)
	}

	wg.Wait()
}

// getNextPeerExpiration returns the minimum duration in which the next peer of the account will expire if it was found.
// If there is no peer that expires this function returns false and a duration of 0.
// This function only considers peers that haven't been expired yet and that are connected.
func (am *DefaultAccountManager) getNextPeerExpiration(ctx context.Context, accountID string) (time.Duration, bool) {
	peersWithExpiry, err := am.Store.GetAccountPeersWithExpiration(ctx, LockingStrengthShare, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get peers with expiration: %v", err)
		return 0, false
	}

	if len(peersWithExpiry) == 0 {
		return 0, false
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account settings: %v", err)
		return 0, false
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
	peersWithInactivity, err := am.Store.GetAccountPeersWithInactivity(ctx, LockingStrengthShare, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get peers with inactivity: %v", err)
		return 0, false
	}

	if len(peersWithInactivity) == 0 {
		return 0, false
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account settings: %v", err)
		return 0, false
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
	peersWithExpiry, err := am.Store.GetAccountPeersWithExpiration(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
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
	peersWithInactivity, err := am.Store.GetAccountPeersWithInactivity(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
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
func (am *DefaultAccountManager) GetPeerGroups(ctx context.Context, accountID, peerID string) ([]*nbgroup.Group, error) {
	groups, err := am.Store.GetAccountGroups(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	peerGroups := make([]*nbgroup.Group, 0)
	for _, group := range groups {
		if slices.Contains(group.Peers, peerID) {
			peerGroups = append(peerGroups, group)
		}
	}

	return peerGroups, nil
}

// getPeerGroupIDs returns the IDs of the groups that the peer is part of.
func (am *DefaultAccountManager) getPeerGroupIDs(ctx context.Context, accountID string, peerID string) ([]string, error) {
	groups, err := am.GetPeerGroups(ctx, accountID, peerID)
	if err != nil {
		return nil, err
	}

	groupIDs := make([]string, 0, len(groups))
	for _, group := range groups {
		groupIDs = append(groupIDs, group.ID)
	}

	return groupIDs, err
}

func (am *DefaultAccountManager) getPeerDNSLabels(ctx context.Context, accountID string) (lookupMap, error) {
	dnsLabels, err := am.Store.GetAccountPeerDNSLabels(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	existingLabels := make(lookupMap)
	for _, label := range dnsLabels {
		existingLabels[label] = struct{}{}
	}
	return existingLabels, nil
}

// IsPeerInActiveGroup checks if the given peer is part of a group that is used
// in an active DNS, route, or ACL configuration.
func (am *DefaultAccountManager) isPeerInActiveGroup(ctx context.Context, accountID, peerID string) (bool, error) {
	peerGroupIDs, err := am.getPeerGroupIDs(ctx, accountID, peerID)
	if err != nil {
		return false, err
	}
	return am.areGroupChangesAffectPeers(ctx, accountID, peerGroupIDs)
}

// deletePeers deletes all specified peers and sends updates to the remote peers.
// Returns a slice of functions to save events after successful peer deletion.
func deletePeers(ctx context.Context, am *DefaultAccountManager, store Store, accountID, userID string, peers []*nbpeer.Peer) ([]func(), error) {
	var peerDeletedEvents []func()

	for _, peer := range peers {
		if err := am.integratedPeerValidator.PeerDeleted(ctx, accountID, peer.ID); err != nil {
			return nil, fmt.Errorf("failed to validate peer: %w", err)
		}

		network, err := store.GetAccountNetwork(ctx, LockingStrengthShare, accountID)
		if err != nil {
			return nil, fmt.Errorf("failed to get account network: %w", err)
		}

		if err = store.DeletePeer(ctx, LockingStrengthUpdate, accountID, peer.ID); err != nil {
			return nil, fmt.Errorf("failed to delete peer: %w", err)
		}

		am.peersUpdateManager.SendUpdate(ctx, peer.ID, &UpdateMessage{
			Update: &proto.SyncResponse{
				RemotePeers:        []*proto.RemotePeerConfig{},
				RemotePeersIsEmpty: true,
				NetworkMap: &proto.NetworkMap{
					Serial:               network.CurrentSerial(),
					RemotePeers:          []*proto.RemotePeerConfig{},
					RemotePeersIsEmpty:   true,
					FirewallRules:        []*proto.FirewallRule{},
					FirewallRulesIsEmpty: true,
				},
			},
			NetworkMap: &NetworkMap{},
		})
		am.peersUpdateManager.CloseChannel(ctx, peer.ID)
		peerDeletedEvents = append(peerDeletedEvents, func() {
			am.StoreEvent(ctx, userID, peer.ID, accountID, activity.PeerRemovedByUser, peer.EventMeta(am.GetDNSDomain()))
		})
	}

	return peerDeletedEvents, nil
}

func ConvertSliceToMap(existingLabels []string) map[string]struct{} {
	labelMap := make(map[string]struct{}, len(existingLabels))
	for _, label := range existingLabels {
		labelMap[label] = struct{}{}
	}
	return labelMap
}
