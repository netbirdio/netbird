package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/management-integrations/additions"

	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
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

	peers := make([]*nbpeer.Peer, 0)
	peersMap := make(map[string]*nbpeer.Peer)
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
		aclPeers, _ := account.getPeerConnectionResources(peer.ID)
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
func (am *DefaultAccountManager) MarkPeerConnected(peerPubKey string, connected bool) error {
	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
	if err != nil {
		return err
	}

	unlock := am.Store.AcquireAccountLock(account.Id)
	defer unlock()

	// ensure that we consider modification happened meanwhile (because we were outside the account lock when we fetched the account)
	account, err = am.Store.GetAccount(account.Id)
	if err != nil {
		return err
	}

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

// UpdatePeer updates peer. Only Peer.Name, Peer.SSHEnabled, and Peer.LoginExpirationEnabled can be updated.
func (am *DefaultAccountManager) UpdatePeer(accountID, userID string, update *nbpeer.Peer) (*nbpeer.Peer, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	peer := account.GetPeer(update.ID)
	if peer == nil {
		return nil, status.Errorf(status.NotFound, "peer %s not found", update.ID)
	}

	update, err = additions.ValidatePeersUpdateRequest(update, peer, userID, accountID, am.eventStore, am.GetDNSDomain())
	if err != nil {
		return nil, err
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
	unlock := am.Store.AcquireAccountLock(accountID)
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
	return account.GetPeerNetworkMap(peer.ID, am.dnsDomain), nil
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
	var account *Account
	var err error
	addedByUser := false
	if len(userID) > 0 {
		addedByUser = true
		account, err = am.Store.GetAccountByUser(userID)
	} else {
		account, err = am.Store.GetAccountBySetupKey(setupKey)
	}
	if err != nil {
		return nil, nil, status.Errorf(status.NotFound, "failed adding new peer: account not found")
	}

	unlock := am.Store.AcquireAccountLock(account.Id)
	defer unlock()

	// ensure that we consider modification happened meanwhile (because we were outside the account lock when we fetched the account)
	account, err = am.Store.GetAccount(account.Id)
	if err != nil {
		return nil, nil, err
	}

	if strings.ToLower(peer.Meta.Hostname) == "iphone" || strings.ToLower(peer.Meta.Hostname) == "ipad" && userID != "" {
		if am.idpManager != nil {
			userdata, err := am.lookupUserInCache(userID, account)
			if err == nil {
				peer.Meta.Hostname = fmt.Sprintf("%s-%s", peer.Meta.Hostname, strings.Split(userdata.Email, "@")[0])
			}
		}
	}

	// This is a handling for the case when the same machine (with the same WireGuard pub key) tries to register twice.
	// Such case is possible when AddPeer function takes long time to finish after AcquireAccountLock (e.g., database is slow)
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

	newPeer := &nbpeer.Peer{
		ID:                     xid.New().String(),
		Key:                    peer.Key,
		SetupKey:               upperKey,
		IP:                     nextIp,
		Meta:                   peer.Meta,
		Name:                   peer.Meta.Hostname,
		DNSLabel:               newLabel,
		UserID:                 userID,
		Status:                 &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()},
		SSHEnabled:             false,
		SSHKey:                 peer.SSHKey,
		LastLogin:              time.Now().UTC(),
		LoginExpirationEnabled: addedByUser,
		Ephemeral:              ephemeral,
	}

	if account.Settings.Extra != nil {
		newPeer = additions.PreparePeer(newPeer, account.Settings.Extra)
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

	opEvent.TargetID = newPeer.ID
	opEvent.Meta = newPeer.EventMeta(am.GetDNSDomain())
	if !addedByUser {
		opEvent.Meta["setup_key_name"] = setupKeyName
	}

	am.StoreEvent(opEvent.InitiatorID, opEvent.TargetID, opEvent.AccountID, opEvent.Activity, opEvent.Meta)

	am.updateAccountPeers(account)

	networkMap := account.GetPeerNetworkMap(newPeer.ID, am.dnsDomain)
	return newPeer, networkMap, nil
}

// SyncPeer checks whether peer is eligible for receiving NetworkMap (authenticated) and returns its NetworkMap if eligible
func (am *DefaultAccountManager) SyncPeer(sync PeerSync) (*nbpeer.Peer, *NetworkMap, error) {
	account, err := am.Store.GetAccountByPeerPubKey(sync.WireGuardPubKey)
	if err != nil {
		if errStatus, ok := status.FromError(err); ok && errStatus.Type() == status.NotFound {
			return nil, nil, status.Errorf(status.Unauthenticated, "peer is not registered")
		}
		return nil, nil, err
	}

	// we found the peer, and we follow a normal login flow
	unlock := am.Store.AcquireAccountLock(account.Id)
	defer unlock()

	// fetch the account from the store once more after acquiring lock to avoid concurrent updates inconsistencies
	account, err = am.Store.GetAccount(account.Id)
	if err != nil {
		return nil, nil, err
	}

	peer, err := account.FindPeerByPubKey(sync.WireGuardPubKey)
	if err != nil {
		return nil, nil, status.Errorf(status.Unauthenticated, "peer is not registered")
	}

	err = checkIfPeerOwnerIsBlocked(peer, account)
	if err != nil {
		return nil, nil, err
	}

	if peerLoginExpired(peer, account) {
		return nil, nil, status.Errorf(status.PermissionDenied, "peer login has expired, please log in once more")
	}
	return peer, account.GetPeerNetworkMap(peer.ID, am.dnsDomain), nil
}

// LoginPeer logs in or registers a peer.
// If peer doesn't exist the function checks whether a setup key or a user is present and registers a new peer if so.
func (am *DefaultAccountManager) LoginPeer(login PeerLogin) (*nbpeer.Peer, *NetworkMap, error) {
	account, err := am.Store.GetAccountByPeerPubKey(login.WireGuardPubKey)

	if err != nil {
		if errStatus, ok := status.FromError(err); ok && errStatus.Type() == status.NotFound {
			// we couldn't find this peer by its public key which can mean that peer hasn't been registered yet.
			// Try registering it.
			return am.AddPeer(login.SetupKey, login.UserID, &nbpeer.Peer{
				Key:    login.WireGuardPubKey,
				Meta:   login.Meta,
				SSHKey: login.SSHKey,
			})
		}
		log.Errorf("failed while logging in peer %s: %v", login.WireGuardPubKey, err)
		return nil, nil, status.Errorf(status.Internal, "failed while logging in peer")
	}

	// we found the peer, and we follow a normal login flow
	unlock := am.Store.AcquireAccountLock(account.Id)
	defer unlock()

	// fetch the account from the store once more after acquiring lock to avoid concurrent updates inconsistencies
	account, err = am.Store.GetAccount(account.Id)
	if err != nil {
		return nil, nil, err
	}

	peer, err := account.FindPeerByPubKey(login.WireGuardPubKey)
	if err != nil {
		return nil, nil, status.Errorf(status.Unauthenticated, "peer is not registered")
	}

	err = checkIfPeerOwnerIsBlocked(peer, account)
	if err != nil {
		return nil, nil, err
	}

	// this flag prevents unnecessary calls to the persistent store.
	shouldStoreAccount := false
	updateRemotePeers := false
	if peerLoginExpired(peer, account) {
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

	peer, updated := updatePeerMeta(peer, login.Meta, account)
	if updated {
		shouldStoreAccount = true
	}

	peer, err = am.checkAndUpdatePeerSSHKey(peer, account, login.SSHKey)
	if err != nil {
		return nil, nil, err
	}

	if shouldStoreAccount {
		err = am.Store.SaveAccount(account)
		if err != nil {
			return nil, nil, err
		}
	}

	if updateRemotePeers {
		am.updateAccountPeers(account)
	}
	return peer, account.GetPeerNetworkMap(peer.ID, am.dnsDomain), nil
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

func peerLoginExpired(peer *nbpeer.Peer, account *Account) bool {
	expired, expiresIn := peer.LoginExpired(account.Settings.PeerLoginExpiration)
	expired = account.Settings.PeerLoginExpirationEnabled && expired
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

	unlock := am.Store.AcquireAccountLock(account.Id)
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
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
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

	for _, p := range userPeers {
		aclPeers, _ := account.getPeerConnectionResources(p.ID)
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

	for _, peer := range peers {
		remotePeerNetworkMap := account.GetPeerNetworkMap(peer.ID, am.dnsDomain)
		update := toSyncResponse(nil, peer, nil, remotePeerNetworkMap, am.GetDNSDomain())
		am.peersUpdateManager.SendUpdate(peer.ID, &UpdateMessage{Update: update})
	}
}
