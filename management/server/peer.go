package server

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
	nbroute "github.com/netbirdio/netbird/route"
)

// PeerSync used as a data object between the gRPC API and AccountManager on Sync request.
type PeerSync struct {
	// WireGuardPubKey is a peers WireGuard public key
	WireGuardPubKey string
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
func (am *DefaultAccountManager) GetPeers(accountID, userID string) ([]*nbpeer.Peer, error) {
	account, err := am.Store.GetAccount(accountID)
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

	if !user.HasAdminPower() && !user.IsServiceUser && account.Settings.RegularUsersViewBlocked {
		return peers, nil
	}

	for _, peer := range account.Peers {
		if !(user.HasAdminPower() || user.IsServiceUser) && user.Id != peer.UserID {
			// only display peers that belong to the current user if the current user is not an admin
			continue
		}
		p := peer.Copy()
		peers = append(peers, p)
		peersMap[peer.ID] = p
	}

	// fetch all the peers that have access to the user's peers
	for _, peer := range peers {
		aclPeers, _ := account.getPeerConnectionResources(peer.ID, approvedPeersMap)
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
func (am *DefaultAccountManager) MarkPeerConnected(peerPubKey string, connected bool, realIP net.IP, account *Account) error {
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
			log.Warnf("failed to get location for peer %s realip: [%s]: %v", peer.ID, realIP.String(), err)
		} else {
			peer.Location.ConnectionIP = realIP
			peer.Location.CountryCode = location.Country.ISOCode
			peer.Location.CityName = location.City.Names.En
			peer.Location.GeoNameID = location.City.GeonameID
			err = am.Store.SavePeerLocation(account.Id, peer)
			if err != nil {
				log.Warnf("could not store location for peer %s: %s", peer.ID, err)
			}
		}
	}

	account.UpdatePeer(peer)

	err = am.Store.SavePeerStatus(account.Id, peer.ID, *newStatus)
	if err != nil {
		return err
	}

	if peer.AddedWithSSOLogin() && peer.LoginExpirationEnabled && account.Settings.PeerLoginExpirationEnabled {
		am.checkAndSchedulePeerLoginExpiration(account)
	}

	if oldStatus.LoginExpired {
		// we need to update other peers because when peer login expires all other peers are notified to disconnect from
		// the expired one. Here we notify them that connection is now allowed again.
		am.updateAccountPeers(account)
	}

	return nil
}

// Determines the current IPv6 status of the peer (including checks for inheritance) and generates a new or removes an
// existing IPv6 address if necessary.
// Additionally, disables IPv6 routes if peer no longer has an IPv6 address.
// Note that this change does not get persisted here.
//
// Returns a boolean that indicates whether the peer and/or the account changed and needs to be updated in the data
// source.
func (am *DefaultAccountManager) DeterminePeerV6(account *Account, peer *nbpeer.Peer) (bool, error) {
	v6Setting := peer.V6Setting
	if peer.V6Setting == nbpeer.V6Auto {
		if peer.Meta.Ipv6Supported {
			for _, group := range account.Groups {
				if group.IPv6Enabled && slices.Contains(group.Peers, peer.ID) {
					v6Setting = nbpeer.V6Enabled
					break
				}
			}
			if v6Setting == nbpeer.V6Auto {
				for _, route := range account.Routes {
					if route.Peer == peer.ID && route.NetworkType == nbroute.IPv6Network {
						v6Setting = nbpeer.V6Enabled
						break
					}
				}
			}
		}

		if v6Setting == nbpeer.V6Auto {
			v6Setting = nbpeer.V6Disabled
		}
	}

	if v6Setting == nbpeer.V6Enabled && peer.IP6 == nil {
		if !peer.Meta.Ipv6Supported {
			return false, status.Errorf(status.PreconditionFailed, "failed allocating new IPv6 for peer %s - peer does not support IPv6", peer.Name)
		}
		if account.Network.Net6 == nil {
			account.Network.Net6 = GenerateNetwork6()
		}
		v6tmp, err := AllocatePeerIP6(*account.Network.Net6, account.getTakenIP6s())
		if err != nil {
			return false, err
		}
		peer.IP6 = &v6tmp
		return true, nil
	} else if v6Setting == nbpeer.V6Disabled && peer.IP6 != nil {
		peer.IP6 = nil

		for _, route := range account.Routes {
			if route.NetworkType == nbroute.IPv6Network {
				route.Enabled = false
				account.Routes[route.ID] = route
			}
		}
		return true, nil
	}
	return false, nil
}

// UpdatePeer updates peer. Only Peer.Name, Peer.SSHEnabled, Peer.V6Setting and Peer.LoginExpirationEnabled can be updated.
func (am *DefaultAccountManager) UpdatePeer(accountID, userID string, update *nbpeer.Peer) (*nbpeer.Peer, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	peer := account.GetPeer(update.ID)
	if peer == nil {
		return nil, status.Errorf(status.NotFound, "peer %s not found", update.ID)
	}

	update, err = am.integratedPeerValidator.ValidatePeer(update, peer, userID, accountID, am.GetDNSDomain(), account.GetPeerGroupsList(peer.ID), account.Settings.Extra)
	if err != nil {
		return nil, err
	}

	if peer.V6Setting != update.V6Setting {
		peer.V6Setting = update.V6Setting
		prevV6 := peer.IP6
		v6StatusChanged, err := am.DeterminePeerV6(account, peer)
		if err != nil {
			return nil, err
		}
		if v6StatusChanged && peer.IP6 != nil {
			am.StoreEvent(userID, peer.IP6.String(), account.Id, activity.PeerIPv6Enabled, peer.EventMeta(am.GetDNSDomain()))
		} else if v6StatusChanged && peer.IP6 == nil {
			am.StoreEvent(userID, prevV6.String(), account.Id, activity.PeerIPv6Disabled, peer.EventMeta(am.GetDNSDomain()))
		}
	}

	if peer.SSHEnabled != update.SSHEnabled {
		peer.SSHEnabled = update.SSHEnabled
		event := activity.PeerSSHEnabled
		if !update.SSHEnabled {
			event = activity.PeerSSHDisabled
		}
		am.StoreEvent(userID, peer.IP.String(), accountID, event, peer.EventMeta(am.GetDNSDomain()))
	}

	if peer.Name != update.Name {
		peer.Name = update.Name

		existingLabels := account.getPeerDNSLabels()

		newLabel, err := getPeerHostLabel(peer.Name, existingLabels)
		if err != nil {
			return nil, err
		}

		peer.DNSLabel = newLabel

		am.StoreEvent(userID, peer.ID, accountID, activity.PeerRenamed, peer.EventMeta(am.GetDNSDomain()))
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
		am.StoreEvent(userID, peer.IP.String(), accountID, event, peer.EventMeta(am.GetDNSDomain()))

		if peer.AddedWithSSOLogin() && peer.LoginExpirationEnabled && account.Settings.PeerLoginExpirationEnabled {
			am.checkAndSchedulePeerLoginExpiration(account)
		}
	}

	account.UpdatePeer(peer)

	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	am.updateAccountPeers(account)

	return peer, nil
}

// deletePeers will delete all specified peers and send updates to the remote peers. Don't call without acquiring account lock
func (am *DefaultAccountManager) deletePeers(account *Account, peerIDs []string, userID string) error {

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

		err := am.integratedPeerValidator.PeerDeleted(account.Id, peer.ID)
		if err != nil {
			return err
		}

		account.DeletePeer(peer.ID)
		am.peersUpdateManager.SendUpdate(peer.ID,
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
			})
		am.peersUpdateManager.CloseChannel(peer.ID)
		am.StoreEvent(userID, peer.ID, account.Id, activity.PeerRemovedByUser, peer.EventMeta(am.GetDNSDomain()))
	}

	return nil
}

// DeletePeer removes peer from the account by its IP
func (am *DefaultAccountManager) DeletePeer(accountID, peerID, userID string) error {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	err = am.deletePeers(account, []string{peerID}, userID)
	if err != nil {
		return err
	}

	err = am.Store.SaveAccount(account)
	if err != nil {
		return err
	}

	am.updateAccountPeers(account)

	return nil
}

// GetNetworkMap returns Network map for a given peer (omits original peer from the Peers result)
func (am *DefaultAccountManager) GetNetworkMap(peerID string) (*NetworkMap, error) {
	account, err := am.Store.GetAccountByPeerID(peerID)
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
	return account.GetPeerNetworkMap(peer.ID, am.dnsDomain, validatedPeers), nil
}

// GetPeerNetwork returns the Network for a given peer
func (am *DefaultAccountManager) GetPeerNetwork(peerID string) (*Network, error) {
	account, err := am.Store.GetAccountByPeerID(peerID)
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
func (am *DefaultAccountManager) AddPeer(setupKey, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, *NetworkMap, error) {
	if setupKey == "" && userID == "" {
		// no auth method provided => reject access
		return nil, nil, status.Errorf(status.Unauthenticated, "no peer auth method provided, please use a setup key or interactive SSO login")
	}

	upperKey := strings.ToUpper(setupKey)
	var accountID string
	var err error
	addedByUser := false
	if len(userID) > 0 {
		addedByUser = true
		accountID, err = am.Store.GetAccountIDByUserID(userID)
	} else {
		accountID, err = am.Store.GetAccountIDBySetupKey(setupKey)
	}
	if err != nil {
		return nil, nil, status.Errorf(status.NotFound, "failed adding new peer: account not found")
	}

	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()

	var account *Account
	// ensure that we consider modification happened meanwhile (because we were outside the account lock when we fetched the account)
	account, err = am.Store.GetAccount(accountID)
	if err != nil {
		return nil, nil, err
	}

	if strings.ToLower(peer.Meta.Hostname) == "iphone" || strings.ToLower(peer.Meta.Hostname) == "ipad" && userID != "" {
		if am.idpManager != nil {
			userdata, err := am.lookupUserInCache(userID, account)
			if err == nil && userdata != nil {
				peer.Meta.Hostname = fmt.Sprintf("%s-%s", peer.Meta.Hostname, strings.Split(userdata.Email, "@")[0])
			}
		}
	}

	// This is a handling for the case when the same machine (with the same WireGuard pub key) tries to register twice.
	// Such case is possible when AddPeer function takes long time to finish after AcquireAccountWriteLock (e.g., database is slow)
	// and the peer disconnects with a timeout and tries to register again.
	// We just check if this machine has been registered before and reject the second registration.
	// The connecting peer should be able to recover with a retry.
	_, err = account.FindPeerByPubKey(peer.Key)
	if err == nil {
		return nil, nil, status.Errorf(status.PreconditionFailed, "peer has been already registered")
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
			return nil, nil, err
		}

		if !sk.IsValid() {
			return nil, nil, status.Errorf(status.PreconditionFailed, "couldn't add peer: setup key is invalid")
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
		return nil, nil, err
	}

	peer.DNSLabel = newLabel
	network := account.Network
	nextIp, err := AllocatePeerIP(network.Net, takenIps)
	if err != nil {
		return nil, nil, err
	}

	registrationTime := time.Now().UTC()

	newPeer := &nbpeer.Peer{
		ID:                     xid.New().String(),
		Key:                    peer.Key,
		SetupKey:               upperKey,
		IP:                     nextIp,
		IP6:                    nil,
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
		V6Setting:              peer.V6Setting, // empty string "" corresponds to "auto"
	}

	// add peer to 'All' group
	group, err := account.GetGroupAll()
	if err != nil {
		return nil, nil, err
	}
	group.Peers = append(group.Peers, newPeer.ID)

	var groupsToAdd []string
	if addedByUser {
		groupsToAdd, err = account.getUserGroups(userID)
		if err != nil {
			return nil, nil, err
		}
	} else {
		groupsToAdd, err = account.getSetupKeyGroups(upperKey)
		if err != nil {
			return nil, nil, err
		}
	}

	if len(groupsToAdd) > 0 {
		for _, s := range groupsToAdd {
			if g, ok := account.Groups[s]; ok && g.Name != "All" {
				g.Peers = append(g.Peers, newPeer.ID)
			}
		}
	}

	newPeer = am.integratedPeerValidator.PreparePeer(account.Id, newPeer, account.GetPeerGroupsList(newPeer.ID), account.Settings.Extra)

	_, err = am.DeterminePeerV6(account, newPeer)
	if err != nil {
		return nil, nil, err
	}

	if addedByUser {
		user, err := account.FindUser(userID)
		if err != nil {
			return nil, nil, status.Errorf(status.Internal, "couldn't find user")
		}
		user.updateLastLogin(newPeer.LastLogin)
	}

	account.Peers[newPeer.ID] = newPeer
	account.Network.IncSerial()
	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, nil, err
	}

	// Account is saved, we can release the lock
	unlock()
	unlock = nil

	opEvent.TargetID = newPeer.ID
	opEvent.Meta = newPeer.EventMeta(am.GetDNSDomain())
	if !addedByUser {
		opEvent.Meta["setup_key_name"] = setupKeyName
	}

	am.StoreEvent(opEvent.InitiatorID, opEvent.TargetID, opEvent.AccountID, opEvent.Activity, opEvent.Meta)

	am.updateAccountPeers(account)

	approvedPeersMap, err := am.GetValidatedPeers(account)
	if err != nil {
		return nil, nil, err
	}
	networkMap := account.GetPeerNetworkMap(newPeer.ID, am.dnsDomain, approvedPeersMap)
	return newPeer, networkMap, nil
}

// SyncPeer checks whether peer is eligible for receiving NetworkMap (authenticated) and returns its NetworkMap if eligible
func (am *DefaultAccountManager) SyncPeer(sync PeerSync, account *Account) (*nbpeer.Peer, *NetworkMap, error) {
	peer, err := account.FindPeerByPubKey(sync.WireGuardPubKey)
	if err != nil {
		return nil, nil, status.NewPeerNotRegisteredError()
	}

	err = checkIfPeerOwnerIsBlocked(peer, account)
	if err != nil {
		return nil, nil, err
	}

	if peerLoginExpired(peer, account.Settings) {
		return nil, nil, status.Errorf(status.PermissionDenied, "peer login has expired, please log in once more")
	}

	peerNotValid, isStatusChanged, err := am.integratedPeerValidator.IsNotValidPeer(account.Id, peer, account.GetPeerGroupsList(peer.ID), account.Settings.Extra)
	if err != nil {
		return nil, nil, err
	}

	if peerNotValid {
		emptyMap := &NetworkMap{
			Network: account.Network.Copy(),
		}
		return peer, emptyMap, nil
	}

	if isStatusChanged {
		am.updateAccountPeers(account)
	}

	validPeersMap, err := am.GetValidatedPeers(account)
	if err != nil {
		return nil, nil, err
	}
	return peer, account.GetPeerNetworkMap(peer.ID, am.dnsDomain, validPeersMap), nil
}

// LoginPeer logs in or registers a peer.
// If peer doesn't exist the function checks whether a setup key or a user is present and registers a new peer if so.
func (am *DefaultAccountManager) LoginPeer(login PeerLogin) (*nbpeer.Peer, *NetworkMap, error) {
	accountID, err := am.Store.GetAccountIDByPeerPubKey(login.WireGuardPubKey)
	if err != nil {
		if errStatus, ok := status.FromError(err); ok && errStatus.Type() == status.NotFound {
			// we couldn't find this peer by its public key which can mean that peer hasn't been registered yet.
			// Try registering it.
			newPeer := &nbpeer.Peer{
				Key:    login.WireGuardPubKey,
				Meta:   login.Meta,
				SSHKey: login.SSHKey,
			}
			if am.geo != nil && login.ConnectionIP != nil {
				location, err := am.geo.Lookup(login.ConnectionIP)
				if err != nil {
					log.Warnf("failed to get location for new peer realip: [%s]: %v", login.ConnectionIP.String(), err)
				} else {
					newPeer.Location.ConnectionIP = login.ConnectionIP
					newPeer.Location.CountryCode = location.Country.ISOCode
					newPeer.Location.CityName = location.City.Names.En
					newPeer.Location.GeoNameID = location.City.GeonameID

				}
			}

			return am.AddPeer(login.SetupKey, login.UserID, newPeer)
		}
		log.Errorf("failed while logging in peer %s: %v", login.WireGuardPubKey, err)
		return nil, nil, status.Errorf(status.Internal, "failed while logging in peer")
	}

	peer, err := am.Store.GetPeerByPeerPubKey(login.WireGuardPubKey)
	if err != nil {
		return nil, nil, status.NewPeerNotRegisteredError()
	}

	accSettings, err := am.Store.GetAccountSettings(accountID)
	if err != nil {
		return nil, nil, status.Errorf(status.Internal, "failed to get account settings: %s", err)
	}

	var isWriteLock bool

	// duplicated logic from after the lock to have an early exit
	expired := peerLoginExpired(peer, accSettings)
	switch {
	case expired:
		if err := checkAuth(login.UserID, peer); err != nil {
			return nil, nil, err
		}
		isWriteLock = true
		log.Debugf("peer login expired, acquiring write lock")

	case peer.UpdateMetaIfNew(login.Meta):
		isWriteLock = true
		log.Debugf("peer changed meta, acquiring write lock")

	default:
		isWriteLock = false
		log.Debugf("peer meta is the same, acquiring read lock")
	}

	var unlock func()

	if isWriteLock {
		unlock = am.Store.AcquireAccountWriteLock(accountID)
	} else {
		unlock = am.Store.AcquireAccountReadLock(accountID)
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()

	// fetch the account from the store once more after acquiring lock to avoid concurrent updates inconsistencies
	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, nil, err
	}

	peer, err = account.FindPeerByPubKey(login.WireGuardPubKey)
	if err != nil {
		return nil, nil, status.NewPeerNotRegisteredError()
	}

	err = checkIfPeerOwnerIsBlocked(peer, account)
	if err != nil {
		return nil, nil, err
	}

	// this flag prevents unnecessary calls to the persistent store.
	shouldStoreAccount := false
	updateRemotePeers := false
	if peerLoginExpired(peer, account.Settings) {
		err = checkAuth(login.UserID, peer)
		if err != nil {
			return nil, nil, err
		}
		// If peer was expired before and if it reached this point, it is re-authenticated.
		// UserID is present, meaning that JWT validation passed successfully in the API layer.
		updatePeerLastLogin(peer, account)
		updateRemotePeers = true
		shouldStoreAccount = true

		// sync user last login with peer last login
		user, err := account.FindUser(login.UserID)
		if err != nil {
			return nil, nil, status.Errorf(status.Internal, "couldn't find user")
		}
		user.updateLastLogin(peer.LastLogin)

		am.StoreEvent(login.UserID, peer.ID, account.Id, activity.UserLoggedInPeer, peer.EventMeta(am.GetDNSDomain()))
	}

	isRequiresApproval, isStatusChanged, err := am.integratedPeerValidator.IsNotValidPeer(account.Id, peer, account.GetPeerGroupsList(peer.ID), account.Settings.Extra)
	if err != nil {
		return nil, nil, err
	}
	peer, updated := updatePeerMeta(peer, login.Meta, account)
	if updated {
		shouldStoreAccount = true
	}

	updated, err = am.DeterminePeerV6(account, peer)
	if err != nil {
		return nil, nil, err
	}
	if updated {
		shouldStoreAccount = true
	}

	peer, err = am.checkAndUpdatePeerSSHKey(peer, account, login.SSHKey)
	if err != nil {
		return nil, nil, err
	}

	if shouldStoreAccount {
		if !isWriteLock {
			log.Errorf("account %s should be stored but is not write locked", accountID)
			return nil, nil, status.Errorf(status.Internal, "account should be stored but is not write locked")
		}
		err = am.Store.SaveAccount(account)
		if err != nil {
			return nil, nil, err
		}
	}
	unlock()
	unlock = nil

	if updateRemotePeers || isStatusChanged {
		am.updateAccountPeers(account)
	}

	if isRequiresApproval {
		emptyMap := &NetworkMap{
			Network: account.Network.Copy(),
		}
		return peer, emptyMap, nil
	}

	approvedPeersMap, err := am.GetValidatedPeers(account)
	if err != nil {
		return nil, nil, err
	}

	return peer, account.GetPeerNetworkMap(peer.ID, am.dnsDomain, approvedPeersMap), nil
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

func checkAuth(loginUserID string, peer *nbpeer.Peer) error {
	if loginUserID == "" {
		// absence of a user ID indicates that JWT wasn't provided.
		return status.Errorf(status.PermissionDenied, "peer login has expired, please log in once more")
	}
	if peer.UserID != loginUserID {
		log.Warnf("user mismatch when logging in peer %s: peer user %s, login user %s ", peer.ID, peer.UserID, loginUserID)
		return status.Errorf(status.Unauthenticated, "can't login")
	}
	return nil
}

func peerLoginExpired(peer *nbpeer.Peer, settings *Settings) bool {
	expired, expiresIn := peer.LoginExpired(settings.PeerLoginExpiration)
	expired = settings.PeerLoginExpirationEnabled && expired
	if expired || peer.Status.LoginExpired {
		log.Debugf("peer's %s login expired %v ago", peer.ID, expiresIn)
		return true
	}
	return false
}

func updatePeerLastLogin(peer *nbpeer.Peer, account *Account) {
	peer.UpdateLastLogin()
	account.UpdatePeer(peer)
}

func (am *DefaultAccountManager) checkAndUpdatePeerSSHKey(peer *nbpeer.Peer, account *Account, newSSHKey string) (*nbpeer.Peer, error) {
	if len(newSSHKey) == 0 {
		log.Debugf("no new SSH key provided for peer %s, skipping update", peer.ID)
		return peer, nil
	}

	if peer.SSHKey == newSSHKey {
		log.Debugf("same SSH key provided for peer %s, skipping update", peer.ID)
		return peer, nil
	}

	peer.SSHKey = newSSHKey
	account.UpdatePeer(peer)

	err := am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	// trigger network map update
	am.updateAccountPeers(account)

	return peer, nil
}

// UpdatePeerSSHKey updates peer's public SSH key
func (am *DefaultAccountManager) UpdatePeerSSHKey(peerID string, sshKey string) error {
	if sshKey == "" {
		log.Debugf("empty SSH key provided for peer %s, skipping update", peerID)
		return nil
	}

	account, err := am.Store.GetAccountByPeerID(peerID)
	if err != nil {
		return err
	}

	unlock := am.Store.AcquireAccountWriteLock(account.Id)
	defer unlock()

	// ensure that we consider modification happened meanwhile (because we were outside the account lock when we fetched the account)
	account, err = am.Store.GetAccount(account.Id)
	if err != nil {
		return err
	}

	peer := account.GetPeer(peerID)
	if peer == nil {
		return status.Errorf(status.NotFound, "peer with ID %s not found", peerID)
	}

	if peer.SSHKey == sshKey {
		log.Debugf("same SSH key provided for peer %s, skipping update", peerID)
		return nil
	}

	peer.SSHKey = sshKey
	account.UpdatePeer(peer)

	err = am.Store.SaveAccount(account)
	if err != nil {
		return err
	}

	// trigger network map update
	am.updateAccountPeers(account)

	return nil
}

// GetPeer for a given accountID, peerID and userID error if not found.
func (am *DefaultAccountManager) GetPeer(accountID, peerID, userID string) (*nbpeer.Peer, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
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
		aclPeers, _ := account.getPeerConnectionResources(p.ID, approvedPeersMap)
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
func (am *DefaultAccountManager) updateAccountPeers(account *Account) {
	peers := account.GetPeers()

	approvedPeersMap, err := am.GetValidatedPeers(account)
	if err != nil {
		log.Errorf("failed send out updates to peers, failed to validate peer: %v", err)
		return
	}
	for _, peer := range peers {
		if !am.peersUpdateManager.HasChannel(peer.ID) {
			log.Tracef("peer %s doesn't have a channel, skipping network map update", peer.ID)
			continue
		}
		remotePeerNetworkMap := account.GetPeerNetworkMap(peer.ID, am.dnsDomain, approvedPeersMap)
		update := toSyncResponse(nil, peer, nil, remotePeerNetworkMap, am.GetDNSDomain())
		am.peersUpdateManager.SendUpdate(peer.ID, &UpdateMessage{Update: update})
	}
}
