package server

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

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

// GetPeers returns a list of peers under the given account filtering out peers that do not belong to a user if
// the current user is not an admin.
func (am *DefaultAccountManager) GetPeers(ctx context.Context, accountID, userID string) ([]*nbpeer.Peer, error) {
	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	approvedPeersMap, err := am.GetValidatedPeers(account)
	if err != nil {
		return nil, err
	}
	peers := make([]*nbpeer.Peer, 0)
	peersMap := make(map[string]*nbpeer.Peer)

	regularUser := !user.HasAdminPower() && !user.IsServiceUser

	if regularUser && account.Settings.RegularUsersViewBlocked {
		return peers, nil
	}

	for _, peer := range account.Peers {
		if regularUser && user.Id != peer.UserID {
			// only display peers that belong to the current user if the current user is not an admin
			continue
		}
		p := peer.Copy()
		peers = append(peers, p)
		peersMap[peer.ID] = p
	}

	if !regularUser {
		return peers, nil
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
func (am *DefaultAccountManager) MarkPeerConnected(ctx context.Context, peerPubKey string, connected bool, realIP net.IP, account *Account) error {
	peer, err := account.FindPeerByPubKey(peerPubKey)
	if err != nil {
		return err
	}

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
			err = am.Store.SavePeerLocation(account.Id, peer)
			if err != nil {
				log.WithContext(ctx).Warnf("could not store location for peer %s: %s", peer.ID, err)
			}
		}
	}

	account.UpdatePeer(peer)

	err = am.Store.SavePeerStatus(account.Id, peer.ID, *newStatus)
	if err != nil {
		return err
	}

	if peer.AddedWithSSOLogin() && peer.LoginExpirationEnabled && account.Settings.PeerLoginExpirationEnabled {
		am.checkAndSchedulePeerLoginExpiration(ctx, account)
	}

	if oldStatus.LoginExpired {
		// we need to update other peers because when peer login expires all other peers are notified to disconnect from
		// the expired one. Here we notify them that connection is now allowed again.
		am.updateAccountPeers(ctx, account)
	}

	return nil
}

// UpdatePeer updates peer. Only Peer.Name, Peer.SSHEnabled, and Peer.LoginExpirationEnabled can be updated.
func (am *DefaultAccountManager) UpdatePeer(ctx context.Context, accountID, userID string, update *nbpeer.Peer) (*nbpeer.Peer, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	peer := account.GetPeer(update.ID)
	if peer == nil {
		return nil, status.Errorf(status.NotFound, "peer %s not found", update.ID)
	}

	update, err = am.integratedPeerValidator.ValidatePeer(ctx, update, peer, userID, accountID, am.GetDNSDomain(), account.GetPeerGroupsList(peer.ID), account.Settings.Extra)
	if err != nil {
		return nil, err
	}

	if peer.SSHEnabled != update.SSHEnabled {
		peer.SSHEnabled = update.SSHEnabled
		event := activity.PeerSSHEnabled
		if !update.SSHEnabled {
			event = activity.PeerSSHDisabled
		}
		am.StoreEvent(ctx, userID, peer.IP.String(), accountID, event, peer.EventMeta(am.GetDNSDomain()))
	}

	peerLabelUpdated := peer.Name != update.Name

	if peerLabelUpdated {
		peer.Name = update.Name

		existingLabels := account.getPeerDNSLabels()

		newLabel, err := getPeerHostLabel(peer.Name, existingLabels)
		if err != nil {
			return nil, err
		}

		peer.DNSLabel = newLabel

		am.StoreEvent(ctx, userID, peer.ID, accountID, activity.PeerRenamed, peer.EventMeta(am.GetDNSDomain()))
	}

	if peer.LoginExpirationEnabled != update.LoginExpirationEnabled {

		if !peer.AddedWithSSOLogin() {
			return nil, status.Errorf(status.PreconditionFailed, "this peer hasn't been added with the SSO login, therefore the login expiration can't be updated")
		}

		peer.LoginExpirationEnabled = update.LoginExpirationEnabled

		event := activity.PeerLoginExpirationEnabled
		if !update.LoginExpirationEnabled {
			event = activity.PeerLoginExpirationDisabled
		}
		am.StoreEvent(ctx, userID, peer.IP.String(), accountID, event, peer.EventMeta(am.GetDNSDomain()))

		if peer.AddedWithSSOLogin() && peer.LoginExpirationEnabled && account.Settings.PeerLoginExpirationEnabled {
			am.checkAndSchedulePeerLoginExpiration(ctx, account)
		}
	}

	account.UpdatePeer(peer)
	err = am.Store.SaveAccount(ctx, account)
	if err != nil {
		return nil, err
	}

	expired, _ := peer.LoginExpired(account.Settings.PeerLoginExpiration)

	if peerLabelUpdated || (expired && peer.LoginExpirationEnabled) {
		am.updateAccountPeers(ctx, account)
	}

	return peer, nil
}

// deletePeers will delete all specified peers and send updates to the remote peers. Don't call without acquiring account lock
func (am *DefaultAccountManager) deletePeers(ctx context.Context, account *Account, peerIDs []string, userID string) error {

	// the first loop is needed to ensure all peers present under the account before modifying, otherwise
	// we might have some inconsistencies
	peers := make([]*nbpeer.Peer, 0, len(peerIDs))
	for _, peerID := range peerIDs {

		peer := account.GetPeer(peerID)
		if peer == nil {
			return status.Errorf(status.NotFound, "peer %s not found", peerID)
		}
		peers = append(peers, peer)
	}

	// the 2nd loop performs the actual modification
	for _, peer := range peers {

		err := am.integratedPeerValidator.PeerDeleted(ctx, account.Id, peer.ID)
		if err != nil {
			return err
		}

		account.DeletePeer(peer.ID)
		am.peersUpdateManager.SendUpdate(ctx, peer.ID,
			&UpdateMessage{
				Update: &proto.SyncResponse{
					// fill those field for backward compatibility
					RemotePeers:        []*proto.RemotePeerConfig{},
					RemotePeersIsEmpty: true,
					// new field
					NetworkMap: &proto.NetworkMap{
						Serial:               account.Network.CurrentSerial(),
						RemotePeers:          []*proto.RemotePeerConfig{},
						RemotePeersIsEmpty:   true,
						FirewallRules:        []*proto.FirewallRule{},
						FirewallRulesIsEmpty: true,
					},
				},
				NetworkMap: &NetworkMap{},
				Checks:     []*posture.Checks{},
			})
		am.peersUpdateManager.CloseChannel(ctx, peer.ID)
		am.StoreEvent(ctx, userID, peer.ID, account.Id, activity.PeerRemovedByUser, peer.EventMeta(am.GetDNSDomain()))
	}

	return nil
}

// DeletePeer removes peer from the account by its IP
func (am *DefaultAccountManager) DeletePeer(ctx context.Context, accountID, peerID, userID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	updateAccountPeers := isPeerInActiveGroup(account, peerID)

	err = am.deletePeers(ctx, account, []string{peerID}, userID)
	if err != nil {
		return err
	}

	err = am.Store.SaveAccount(ctx, account)
	if err != nil {
		return err
	}

	if updateAccountPeers {
		am.updateAccountPeers(ctx, account)
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
	var accountID string
	var err error
	addedByUser := false
	if len(userID) > 0 {
		addedByUser = true
		accountID, err = am.Store.GetAccountIDByUserID(userID)
	} else {
		accountID, err = am.Store.GetAccountIDBySetupKey(ctx, setupKey)
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

	var account *Account
	// ensure that we consider modification happened meanwhile (because we were outside the account lock when we fetched the account)
	account, err = am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, nil, nil, err
	}

	if strings.ToLower(peer.Meta.Hostname) == "iphone" || strings.ToLower(peer.Meta.Hostname) == "ipad" && userID != "" {
		if am.idpManager != nil {
			userdata, err := am.lookupUserInCache(ctx, userID, account)
			if err == nil && userdata != nil {
				peer.Meta.Hostname = fmt.Sprintf("%s-%s", peer.Meta.Hostname, strings.Split(userdata.Email, "@")[0])
			}
		}
	}

	// This is a handling for the case when the same machine (with the same WireGuard pub key) tries to register twice.
	// Such case is possible when AddPeer function takes long time to finish after AcquireWriteLockByUID (e.g., database is slow)
	// and the peer disconnects with a timeout and tries to register again.
	// We just check if this machine has been registered before and reject the second registration.
	// The connecting peer should be able to recover with a retry.
	_, err = account.FindPeerByPubKey(peer.Key)
	if err == nil {
		return nil, nil, nil, status.Errorf(status.PreconditionFailed, "peer has been already registered")
	}

	opEvent := &activity.Event{
		Timestamp: time.Now().UTC(),
		AccountID: account.Id,
	}

	var ephemeral bool
	setupKeyName := ""
	if !addedByUser {
		// validate the setup key if adding with a key
		sk, err := account.FindSetupKey(upperKey)
		if err != nil {
			return nil, nil, nil, err
		}

		if !sk.IsValid() {
			return nil, nil, nil, status.Errorf(status.PreconditionFailed, "couldn't add peer: setup key is invalid")
		}

		account.SetupKeys[sk.Key] = sk.IncrementUsage()
		opEvent.InitiatorID = sk.Id
		opEvent.Activity = activity.PeerAddedWithSetupKey
		ephemeral = sk.Ephemeral
		setupKeyName = sk.Name
	} else {
		opEvent.InitiatorID = userID
		opEvent.Activity = activity.PeerAddedByUser
	}

	takenIps := account.getTakenIPs()
	existingLabels := account.getPeerDNSLabels()

	newLabel, err := getPeerHostLabel(peer.Meta.Hostname, existingLabels)
	if err != nil {
		return nil, nil, nil, err
	}

	peer.DNSLabel = newLabel
	network := account.Network
	nextIp, err := AllocatePeerIP(network.Net, takenIps)
	if err != nil {
		return nil, nil, nil, err
	}

	registrationTime := time.Now().UTC()

	newPeer := &nbpeer.Peer{
		ID:                     xid.New().String(),
		Key:                    peer.Key,
		SetupKey:               upperKey,
		IP:                     nextIp,
		Meta:                   peer.Meta,
		Name:                   peer.Meta.Hostname,
		DNSLabel:               newLabel,
		UserID:                 userID,
		Status:                 &nbpeer.PeerStatus{Connected: false, LastSeen: registrationTime},
		SSHEnabled:             false,
		SSHKey:                 peer.SSHKey,
		LastLogin:              registrationTime,
		CreatedAt:              registrationTime,
		LoginExpirationEnabled: addedByUser,
		Ephemeral:              ephemeral,
		Location:               peer.Location,
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

	// add peer to 'All' group
	group, err := account.GetGroupAll()
	if err != nil {
		return nil, nil, nil, err
	}
	group.Peers = append(group.Peers, newPeer.ID)

	var groupsToAdd []string
	if addedByUser {
		groupsToAdd, err = account.getUserGroups(userID)
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		groupsToAdd, err = account.getSetupKeyGroups(upperKey)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	if len(groupsToAdd) > 0 {
		for _, s := range groupsToAdd {
			if g, ok := account.Groups[s]; ok && g.Name != "All" {
				g.Peers = append(g.Peers, newPeer.ID)
			}
		}
	}

	newPeer = am.integratedPeerValidator.PreparePeer(ctx, account.Id, newPeer, account.GetPeerGroupsList(newPeer.ID), account.Settings.Extra)

	if addedByUser {
		user, err := account.FindUser(userID)
		if err != nil {
			return nil, nil, nil, status.Errorf(status.Internal, "couldn't find user")
		}
		user.updateLastLogin(newPeer.LastLogin)
	}

	account.Peers[newPeer.ID] = newPeer
	account.Network.IncSerial()
	err = am.Store.SaveAccount(ctx, account)
	if err != nil {
		return nil, nil, nil, err
	}

	// Account is saved, we can release the lock
	unlock()
	unlock = nil

	opEvent.TargetID = newPeer.ID
	opEvent.Meta = newPeer.EventMeta(am.GetDNSDomain())
	if !addedByUser {
		opEvent.Meta["setup_key_name"] = setupKeyName
	}

	am.StoreEvent(ctx, opEvent.InitiatorID, opEvent.TargetID, opEvent.AccountID, opEvent.Activity, opEvent.Meta)

	if areGroupChangesAffectPeers(account, groupsToAdd) {
		am.updateAccountPeers(ctx, account)
	}

	approvedPeersMap, err := am.GetValidatedPeers(account)
	if err != nil {
		return nil, nil, nil, err
	}

	postureChecks := am.getPeerPostureChecks(account, peer)
	customZone := account.GetPeersCustomZone(ctx, am.dnsDomain)
	networkMap := account.GetPeerNetworkMap(ctx, newPeer.ID, customZone, approvedPeersMap, am.metrics.AccountManagerMetrics())
	return newPeer, networkMap, postureChecks, nil
}

// SyncPeer checks whether peer is eligible for receiving NetworkMap (authenticated) and returns its NetworkMap if eligible
func (am *DefaultAccountManager) SyncPeer(ctx context.Context, sync PeerSync, account *Account) (*nbpeer.Peer, *NetworkMap, []*posture.Checks, error) {
	peer, err := account.FindPeerByPubKey(sync.WireGuardPubKey)
	if err != nil {
		return nil, nil, nil, status.NewPeerNotRegisteredError()
	}

	err = checkIfPeerOwnerIsBlocked(peer, account)
	if err != nil {
		return nil, nil, nil, err
	}

	if peerLoginExpired(ctx, peer, account.Settings) {
		return nil, nil, nil, status.NewPeerLoginExpiredError()
	}

	peer, updated := updatePeerMeta(peer, sync.Meta, account)
	if updated {
		err = am.Store.SavePeer(ctx, account.Id, peer)
		if err != nil {
			return nil, nil, nil, err
		}

		if sync.UpdateAccountPeers {
			am.updateAccountPeers(ctx, account)
		}
	}

	peerNotValid, isStatusChanged, err := am.integratedPeerValidator.IsNotValidPeer(ctx, account.Id, peer, account.GetPeerGroupsList(peer.ID), account.Settings.Extra)
	if err != nil {
		return nil, nil, nil, err
	}

	if peerNotValid {
		emptyMap := &NetworkMap{
			Network: account.Network.Copy(),
		}
		return peer, emptyMap, nil, nil
	}

	peer, peerMetaUpdated := updatePeerMeta(peer, sync.Meta, account)
	if peerMetaUpdated {
		err = am.Store.SaveAccount(ctx, account)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	if isStatusChanged || (peerMetaUpdated && sync.UpdateAccountPeers) {
		am.updateAccountPeers(ctx, account)
	}

	validPeersMap, err := am.GetValidatedPeers(account)
	if err != nil {
		return nil, nil, nil, err
	}
	postureChecks := am.getPeerPostureChecks(account, peer)

	customZone := account.GetPeersCustomZone(ctx, am.dnsDomain)
	return peer, account.GetPeerNetworkMap(ctx, peer.ID, customZone, validPeersMap, am.metrics.AccountManagerMetrics()), postureChecks, nil
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
		err = am.checkIFPeerNeedsLoginWithoutLock(ctx, accountID, login)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()

	// fetch the account from the store once more after acquiring lock to avoid concurrent updates inconsistencies
	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, nil, nil, err
	}

	peer, err := account.FindPeerByPubKey(login.WireGuardPubKey)
	if err != nil {
		return nil, nil, nil, status.NewPeerNotRegisteredError()
	}

	err = checkIfPeerOwnerIsBlocked(peer, account)
	if err != nil {
		return nil, nil, nil, err
	}

	// this flag prevents unnecessary calls to the persistent store.
	shouldStorePeer := false
	updateRemotePeers := false
	if peerLoginExpired(ctx, peer, account.Settings) {
		err = am.handleExpiredPeer(ctx, login, account, peer)
		if err != nil {
			return nil, nil, nil, err
		}
		updateRemotePeers = true
		shouldStorePeer = true
	}

	isRequiresApproval, isStatusChanged, err := am.integratedPeerValidator.IsNotValidPeer(ctx, account.Id, peer, account.GetPeerGroupsList(peer.ID), account.Settings.Extra)
	if err != nil {
		return nil, nil, nil, err
	}

	peer, updated := updatePeerMeta(peer, login.Meta, account)
	if updated {
		shouldStorePeer = true
	}

	if peer.SSHKey != login.SSHKey {
		peer.SSHKey = login.SSHKey
		shouldStorePeer = true
	}

	if shouldStorePeer {
		err = am.Store.SavePeer(ctx, accountID, peer)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	unlock()
	unlock = nil

	if updateRemotePeers || isStatusChanged {
		am.updateAccountPeers(ctx, account)
	}

	return am.getValidatedPeerWithMap(ctx, isRequiresApproval, account, peer)
}

// checkIFPeerNeedsLoginWithoutLock checks if the peer needs login without acquiring the account lock. The check validate if the peer was not added via SSO
// and if the peer login is expired.
// The NetBird client doesn't have a way to check if the peer needs login besides sending a login request
// with no JWT token and usually no setup-key. As the client can send up to two login request to check if it is expired
// and before starting the engine, we do the checks without an account lock to avoid piling up requests.
func (am *DefaultAccountManager) checkIFPeerNeedsLoginWithoutLock(ctx context.Context, accountID string, login PeerLogin) error {
	peer, err := am.Store.GetPeerByPeerPubKey(ctx, login.WireGuardPubKey)
	if err != nil {
		return err
	}

	// if the peer was not added with SSO login we can exit early because peers activated with setup-key
	// doesn't expire, and we avoid extra databases calls.
	if !peer.AddedWithSSOLogin() {
		return nil
	}

	settings, err := am.Store.GetAccountSettings(ctx, accountID)
	if err != nil {
		return err
	}

	if peerLoginExpired(ctx, peer, settings) {
		return status.NewPeerLoginExpiredError()
	}

	return nil
}

func (am *DefaultAccountManager) getValidatedPeerWithMap(ctx context.Context, isRequiresApproval bool, account *Account, peer *nbpeer.Peer) (*nbpeer.Peer, *NetworkMap, []*posture.Checks, error) {
	var postureChecks []*posture.Checks

	if isRequiresApproval {
		emptyMap := &NetworkMap{
			Network: account.Network.Copy(),
		}
		return peer, emptyMap, nil, nil
	}

	approvedPeersMap, err := am.GetValidatedPeers(account)
	if err != nil {
		return nil, nil, nil, err
	}
	postureChecks = am.getPeerPostureChecks(account, peer)

	customZone := account.GetPeersCustomZone(ctx, am.dnsDomain)
	return peer, account.GetPeerNetworkMap(ctx, peer.ID, customZone, approvedPeersMap, am.metrics.AccountManagerMetrics()), postureChecks, nil
}

func (am *DefaultAccountManager) handleExpiredPeer(ctx context.Context, login PeerLogin, account *Account, peer *nbpeer.Peer) error {
	err := checkAuth(ctx, login.UserID, peer)
	if err != nil {
		return err
	}
	// If peer was expired before and if it reached this point, it is re-authenticated.
	// UserID is present, meaning that JWT validation passed successfully in the API layer.
	updatePeerLastLogin(peer, account)

	// sync user last login with peer last login
	user, err := account.FindUser(login.UserID)
	if err != nil {
		return status.Errorf(status.Internal, "couldn't find user")
	}

	err = am.Store.SaveUserLastLogin(account.Id, user.Id, peer.LastLogin)
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, login.UserID, peer.ID, account.Id, activity.UserLoggedInPeer, peer.EventMeta(am.GetDNSDomain()))
	return nil
}

func checkIfPeerOwnerIsBlocked(peer *nbpeer.Peer, account *Account) error {
	if peer.AddedWithSSOLogin() {
		user, err := account.FindUser(peer.UserID)
		if err != nil {
			return status.Errorf(status.PermissionDenied, "user doesn't exist")
		}
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

func updatePeerLastLogin(peer *nbpeer.Peer, account *Account) {
	peer.UpdateLastLogin()
	account.UpdatePeer(peer)
}

// GetPeer for a given accountID, peerID and userID error if not found.
func (am *DefaultAccountManager) GetPeer(ctx context.Context, accountID, peerID, userID string) (*nbpeer.Peer, error) {
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

	if !user.HasAdminPower() && !user.IsServiceUser && account.Settings.RegularUsersViewBlocked {
		return nil, status.Errorf(status.Internal, "user %s has no access to his own peer %s under account %s", userID, peerID, accountID)
	}

	peer := account.GetPeer(peerID)
	if peer == nil {
		return nil, status.Errorf(status.NotFound, "peer with %s not found under account %s", peerID, accountID)
	}

	// if admin or user owns this peer, return peer
	if user.HasAdminPower() || user.IsServiceUser || peer.UserID == userID {
		return peer, nil
	}

	// it is also possible that user doesn't own the peer but some of his peers have access to it,
	// this is a valid case, show the peer as well.
	userPeers, err := account.FindUserPeers(userID)
	if err != nil {
		return nil, err
	}

	approvedPeersMap, err := am.GetValidatedPeers(account)
	if err != nil {
		return nil, err
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

func updatePeerMeta(peer *nbpeer.Peer, meta nbpeer.PeerSystemMeta, account *Account) (*nbpeer.Peer, bool) {
	if peer.UpdateMetaIfNew(meta) {
		account.UpdatePeer(peer)
		return peer, true
	}
	return peer, false
}

// updateAccountPeers updates all peers that belong to an account.
// Should be called when changes have to be synced to peers.
func (am *DefaultAccountManager) updateAccountPeers(ctx context.Context, account *Account) {
	start := time.Now()
	defer func() {
		if am.metrics != nil {
			am.metrics.AccountManagerMetrics().CountUpdateAccountPeersDuration(time.Since(start))
		}
	}()

	peers := account.GetPeers()

	approvedPeersMap, err := am.GetValidatedPeers(account)
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

			postureChecks := am.getPeerPostureChecks(account, p)
			remotePeerNetworkMap := account.GetPeerNetworkMap(ctx, p.ID, customZone, approvedPeersMap, am.metrics.AccountManagerMetrics())
			update := toSyncResponse(ctx, nil, p, nil, remotePeerNetworkMap, am.GetDNSDomain(), postureChecks, dnsCache)
			am.peersUpdateManager.SendUpdate(ctx, p.ID, &UpdateMessage{Update: update, NetworkMap: remotePeerNetworkMap, Checks: postureChecks})
		}(peer)
	}

	wg.Wait()
}

// IsPeerInActiveGroup checks if the given peer is part of a group that is used
// in an active DNS, route, or ACL configuration.
func isPeerInActiveGroup(account *Account, peerID string) bool {
	peerGroupIDs := make([]string, 0)
	for _, group := range account.Groups {
		if slices.Contains(group.Peers, peerID) {
			peerGroupIDs = append(peerGroupIDs, group.ID)
		}
	}
	return areGroupChangesAffectPeers(account, peerGroupIDs)
}
