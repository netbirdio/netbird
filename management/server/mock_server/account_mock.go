package mock_server

import (
	"net"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/route"
)

type MockAccountManager struct {
	GetOrCreateAccountByUserFunc func(userId, domain string) (*server.Account, error)
	CreateSetupKeyFunc           func(accountId string, keyName string, keyType server.SetupKeyType,
		expiresIn time.Duration, autoGroups []string, usageLimit int, userID string, ephemeral bool) (*server.SetupKey, error)
	GetSetupKeyFunc                     func(accountID, userID, keyID string) (*server.SetupKey, error)
	GetAccountByUserOrAccountIdFunc     func(userId, accountId, domain string) (*server.Account, error)
	GetUserFunc                         func(claims jwtclaims.AuthorizationClaims) (*server.User, error)
	ListUsersFunc                       func(accountID string) ([]*server.User, error)
	GetPeersFunc                        func(accountID, userID string) ([]*nbpeer.Peer, error)
	MarkPeerConnectedFunc               func(peerKey string, connected bool, realIP net.IP) error
	SyncAndMarkPeerFunc                 func(peerPubKey string, realIP net.IP) (*nbpeer.Peer, *server.NetworkMap, error)
	DeletePeerFunc                      func(accountID, peerKey, userID string) error
	GetNetworkMapFunc                   func(peerKey string) (*server.NetworkMap, error)
	GetPeerNetworkFunc                  func(peerKey string) (*server.Network, error)
	AddPeerFunc                         func(setupKey string, userId string, peer *nbpeer.Peer) (*nbpeer.Peer, *server.NetworkMap, error)
	GetGroupFunc                        func(accountID, groupID, userID string) (*group.Group, error)
	GetAllGroupsFunc                    func(accountID, userID string) ([]*group.Group, error)
	GetGroupByNameFunc                  func(accountID, groupName string) (*group.Group, error)
	SaveGroupFunc                       func(accountID, userID string, group *group.Group) error
	DeleteGroupFunc                     func(accountID, userId, groupID string) error
	ListGroupsFunc                      func(accountID string) ([]*group.Group, error)
	GroupAddPeerFunc                    func(accountID, groupID, peerID string) error
	GroupDeletePeerFunc                 func(accountID, groupID, peerID string) error
	DeleteRuleFunc                      func(accountID, ruleID, userID string) error
	GetPolicyFunc                       func(accountID, policyID, userID string) (*server.Policy, error)
	SavePolicyFunc                      func(accountID, userID string, policy *server.Policy) error
	DeletePolicyFunc                    func(accountID, policyID, userID string) error
	ListPoliciesFunc                    func(accountID, userID string) ([]*server.Policy, error)
	GetUsersFromAccountFunc             func(accountID, userID string) ([]*server.UserInfo, error)
	GetAccountFromPATFunc               func(pat string) (*server.Account, *server.User, *server.PersonalAccessToken, error)
	MarkPATUsedFunc                     func(pat string) error
	UpdatePeerMetaFunc                  func(peerID string, meta nbpeer.PeerSystemMeta) error
	UpdatePeerSSHKeyFunc                func(peerID string, sshKey string) error
	UpdatePeerFunc                      func(accountID, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, error)
	CreateRouteFunc                     func(accountID, prefix, peer string, peerGroups []string, description string, netID route.NetID, masquerade bool, metric int, groups []string, enabled bool, userID string) (*route.Route, error)
	GetRouteFunc                        func(accountID string, routeID route.ID, userID string) (*route.Route, error)
	SaveRouteFunc                       func(accountID string, userID string, route *route.Route) error
	DeleteRouteFunc                     func(accountID string, routeID route.ID, userID string) error
	ListRoutesFunc                      func(accountID, userID string) ([]*route.Route, error)
	SaveSetupKeyFunc                    func(accountID string, key *server.SetupKey, userID string) (*server.SetupKey, error)
	ListSetupKeysFunc                   func(accountID, userID string) ([]*server.SetupKey, error)
	SaveUserFunc                        func(accountID, userID string, user *server.User) (*server.UserInfo, error)
	SaveOrAddUserFunc                   func(accountID, userID string, user *server.User, addIfNotExists bool) (*server.UserInfo, error)
	DeleteUserFunc                      func(accountID string, initiatorUserID string, targetUserID string) error
	CreatePATFunc                       func(accountID string, initiatorUserID string, targetUserId string, tokenName string, expiresIn int) (*server.PersonalAccessTokenGenerated, error)
	DeletePATFunc                       func(accountID string, initiatorUserID string, targetUserId string, tokenID string) error
	GetPATFunc                          func(accountID string, initiatorUserID string, targetUserId string, tokenID string) (*server.PersonalAccessToken, error)
	GetAllPATsFunc                      func(accountID string, initiatorUserID string, targetUserId string) ([]*server.PersonalAccessToken, error)
	GetNameServerGroupFunc              func(accountID, userID, nsGroupID string) (*nbdns.NameServerGroup, error)
	CreateNameServerGroupFunc           func(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string, searchDomainsEnabled bool) (*nbdns.NameServerGroup, error)
	SaveNameServerGroupFunc             func(accountID, userID string, nsGroupToSave *nbdns.NameServerGroup) error
	DeleteNameServerGroupFunc           func(accountID, nsGroupID, userID string) error
	ListNameServerGroupsFunc            func(accountID string, userID string) ([]*nbdns.NameServerGroup, error)
	CreateUserFunc                      func(accountID, userID string, key *server.UserInfo) (*server.UserInfo, error)
	GetAccountFromTokenFunc             func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error)
	CheckUserAccessByJWTGroupsFunc      func(claims jwtclaims.AuthorizationClaims) error
	DeleteAccountFunc                   func(accountID, userID string) error
	GetDNSDomainFunc                    func() string
	StoreEventFunc                      func(initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any)
	GetEventsFunc                       func(accountID, userID string) ([]*activity.Event, error)
	GetDNSSettingsFunc                  func(accountID, userID string) (*server.DNSSettings, error)
	SaveDNSSettingsFunc                 func(accountID, userID string, dnsSettingsToSave *server.DNSSettings) error
	GetPeerFunc                         func(accountID, peerID, userID string) (*nbpeer.Peer, error)
	UpdateAccountSettingsFunc           func(accountID, userID string, newSettings *server.Settings) (*server.Account, error)
	LoginPeerFunc                       func(login server.PeerLogin) (*nbpeer.Peer, *server.NetworkMap, error)
	SyncPeerFunc                        func(sync server.PeerSync, account *server.Account) (*nbpeer.Peer, *server.NetworkMap, error)
	InviteUserFunc                      func(accountID string, initiatorUserID string, targetUserEmail string) error
	GetAllConnectedPeersFunc            func() (map[string]struct{}, error)
	HasConnectedChannelFunc             func(peerID string) bool
	GetExternalCacheManagerFunc         func() server.ExternalCacheManager
	GetPostureChecksFunc                func(accountID, postureChecksID, userID string) (*posture.Checks, error)
	SavePostureChecksFunc               func(accountID, userID string, postureChecks *posture.Checks) error
	DeletePostureChecksFunc             func(accountID, postureChecksID, userID string) error
	ListPostureChecksFunc               func(accountID, userID string) ([]*posture.Checks, error)
	GetIdpManagerFunc                   func() idp.Manager
	UpdateIntegratedValidatorGroupsFunc func(accountID string, userID string, groups []string) error
	GroupValidationFunc                 func(accountId string, groups []string) (bool, error)
	FindExistingPostureCheckFunc        func(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error)
}

func (am *MockAccountManager) SyncAndMarkPeer(peerPubKey string, realIP net.IP) (*nbpeer.Peer, *server.NetworkMap, error) {
	if am.SyncAndMarkPeerFunc != nil {
		return am.SyncAndMarkPeerFunc(peerPubKey, realIP)
	}
	return nil, nil, status.Errorf(codes.Unimplemented, "method MarkPeerConnected is not implemented")
}

func (am *MockAccountManager) CancelPeerRoutines(peer *nbpeer.Peer) error {
	// TODO implement me
	panic("implement me")
}

func (am *MockAccountManager) GetValidatedPeers(account *server.Account) (map[string]struct{}, error) {
	approvedPeers := make(map[string]struct{})
	for id := range account.Peers {
		approvedPeers[id] = struct{}{}
	}
	return approvedPeers, nil
}

// GetGroup mock implementation of GetGroup from server.AccountManager interface
func (am *MockAccountManager) GetGroup(accountId, groupID, userID string) (*group.Group, error) {
	if am.GetGroupFunc != nil {
		return am.GetGroupFunc(accountId, groupID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetGroup is not implemented")
}

// GetAllGroups mock implementation of GetAllGroups from server.AccountManager interface
func (am *MockAccountManager) GetAllGroups(accountID, userID string) ([]*group.Group, error) {
	if am.GetAllGroupsFunc != nil {
		return am.GetAllGroupsFunc(accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAllGroups is not implemented")
}

// GetUsersFromAccount mock implementation of GetUsersFromAccount from server.AccountManager interface
func (am *MockAccountManager) GetUsersFromAccount(accountID string, userID string) ([]*server.UserInfo, error) {
	if am.GetUsersFromAccountFunc != nil {
		return am.GetUsersFromAccountFunc(accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetUsersFromAccount is not implemented")
}

// DeletePeer mock implementation of DeletePeer from server.AccountManager interface
func (am *MockAccountManager) DeletePeer(accountID, peerID, userID string) error {
	if am.DeletePeerFunc != nil {
		return am.DeletePeerFunc(accountID, peerID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeletePeer is not implemented")
}

// GetOrCreateAccountByUser mock implementation of GetOrCreateAccountByUser from server.AccountManager interface
func (am *MockAccountManager) GetOrCreateAccountByUser(
	userId, domain string,
) (*server.Account, error) {
	if am.GetOrCreateAccountByUserFunc != nil {
		return am.GetOrCreateAccountByUserFunc(userId, domain)
	}
	return nil, status.Errorf(
		codes.Unimplemented,
		"method GetOrCreateAccountByUser is not implemented",
	)
}

// CreateSetupKey mock implementation of CreateSetupKey from server.AccountManager interface
func (am *MockAccountManager) CreateSetupKey(
	accountID string,
	keyName string,
	keyType server.SetupKeyType,
	expiresIn time.Duration,
	autoGroups []string,
	usageLimit int,
	userID string,
	ephemeral bool,
) (*server.SetupKey, error) {
	if am.CreateSetupKeyFunc != nil {
		return am.CreateSetupKeyFunc(accountID, keyName, keyType, expiresIn, autoGroups, usageLimit, userID, ephemeral)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateSetupKey is not implemented")
}

// GetAccountByUserOrAccountID mock implementation of GetAccountByUserOrAccountID from server.AccountManager interface
func (am *MockAccountManager) GetAccountByUserOrAccountID(
	userId, accountId, domain string,
) (*server.Account, error) {
	if am.GetAccountByUserOrAccountIdFunc != nil {
		return am.GetAccountByUserOrAccountIdFunc(userId, accountId, domain)
	}
	return nil, status.Errorf(
		codes.Unimplemented,
		"method GetAccountByUserOrAccountID is not implemented",
	)
}

// MarkPeerConnected mock implementation of MarkPeerConnected from server.AccountManager interface
func (am *MockAccountManager) MarkPeerConnected(peerKey string, connected bool, realIP net.IP, account *server.Account) error {
	if am.MarkPeerConnectedFunc != nil {
		return am.MarkPeerConnectedFunc(peerKey, connected, realIP)
	}
	return status.Errorf(codes.Unimplemented, "method MarkPeerConnected is not implemented")
}

// GetAccountFromPAT mock implementation of GetAccountFromPAT from server.AccountManager interface
func (am *MockAccountManager) GetAccountFromPAT(pat string) (*server.Account, *server.User, *server.PersonalAccessToken, error) {
	if am.GetAccountFromPATFunc != nil {
		return am.GetAccountFromPATFunc(pat)
	}
	return nil, nil, nil, status.Errorf(codes.Unimplemented, "method GetAccountFromPAT is not implemented")
}

// DeleteAccount mock implementation of DeleteAccount from server.AccountManager interface
func (am *MockAccountManager) DeleteAccount(accountID, userID string) error {
	if am.DeleteAccountFunc != nil {
		return am.DeleteAccountFunc(accountID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteAccount is not implemented")
}

// MarkPATUsed mock implementation of MarkPATUsed from server.AccountManager interface
func (am *MockAccountManager) MarkPATUsed(pat string) error {
	if am.MarkPATUsedFunc != nil {
		return am.MarkPATUsedFunc(pat)
	}
	return status.Errorf(codes.Unimplemented, "method MarkPATUsed is not implemented")
}

// CreatePAT mock implementation of GetPAT from server.AccountManager interface
func (am *MockAccountManager) CreatePAT(accountID string, initiatorUserID string, targetUserID string, name string, expiresIn int) (*server.PersonalAccessTokenGenerated, error) {
	if am.CreatePATFunc != nil {
		return am.CreatePATFunc(accountID, initiatorUserID, targetUserID, name, expiresIn)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreatePAT is not implemented")
}

// DeletePAT mock implementation of DeletePAT from server.AccountManager interface
func (am *MockAccountManager) DeletePAT(accountID string, initiatorUserID string, targetUserID string, tokenID string) error {
	if am.DeletePATFunc != nil {
		return am.DeletePATFunc(accountID, initiatorUserID, targetUserID, tokenID)
	}
	return status.Errorf(codes.Unimplemented, "method DeletePAT is not implemented")
}

// GetPAT mock implementation of GetPAT from server.AccountManager interface
func (am *MockAccountManager) GetPAT(accountID string, initiatorUserID string, targetUserID string, tokenID string) (*server.PersonalAccessToken, error) {
	if am.GetPATFunc != nil {
		return am.GetPATFunc(accountID, initiatorUserID, targetUserID, tokenID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPAT is not implemented")
}

// GetAllPATs mock implementation of GetAllPATs from server.AccountManager interface
func (am *MockAccountManager) GetAllPATs(accountID string, initiatorUserID string, targetUserID string) ([]*server.PersonalAccessToken, error) {
	if am.GetAllPATsFunc != nil {
		return am.GetAllPATsFunc(accountID, initiatorUserID, targetUserID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAllPATs is not implemented")
}

// GetNetworkMap mock implementation of GetNetworkMap from server.AccountManager interface
func (am *MockAccountManager) GetNetworkMap(peerKey string) (*server.NetworkMap, error) {
	if am.GetNetworkMapFunc != nil {
		return am.GetNetworkMapFunc(peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetNetworkMap is not implemented")
}

// GetPeerNetwork mock implementation of GetPeerNetwork from server.AccountManager interface
func (am *MockAccountManager) GetPeerNetwork(peerKey string) (*server.Network, error) {
	if am.GetPeerNetworkFunc != nil {
		return am.GetPeerNetworkFunc(peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeerNetwork is not implemented")
}

// AddPeer mock implementation of AddPeer from server.AccountManager interface
func (am *MockAccountManager) AddPeer(
	setupKey string,
	userId string,
	peer *nbpeer.Peer,
) (*nbpeer.Peer, *server.NetworkMap, error) {
	if am.AddPeerFunc != nil {
		return am.AddPeerFunc(setupKey, userId, peer)
	}
	return nil, nil, status.Errorf(codes.Unimplemented, "method AddPeer is not implemented")
}

// GetGroupByName mock implementation of GetGroupByName from server.AccountManager interface
func (am *MockAccountManager) GetGroupByName(accountID, groupName string) (*group.Group, error) {
	if am.GetGroupFunc != nil {
		return am.GetGroupByNameFunc(accountID, groupName)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetGroupByName is not implemented")
}

// SaveGroup mock implementation of SaveGroup from server.AccountManager interface
func (am *MockAccountManager) SaveGroup(accountID, userID string, group *group.Group) error {
	if am.SaveGroupFunc != nil {
		return am.SaveGroupFunc(accountID, userID, group)
	}
	return status.Errorf(codes.Unimplemented, "method SaveGroup is not implemented")
}

// DeleteGroup mock implementation of DeleteGroup from server.AccountManager interface
func (am *MockAccountManager) DeleteGroup(accountId, userId, groupID string) error {
	if am.DeleteGroupFunc != nil {
		return am.DeleteGroupFunc(accountId, userId, groupID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteGroup is not implemented")
}

// ListGroups mock implementation of ListGroups from server.AccountManager interface
func (am *MockAccountManager) ListGroups(accountID string) ([]*group.Group, error) {
	if am.ListGroupsFunc != nil {
		return am.ListGroupsFunc(accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListGroups is not implemented")
}

// GroupAddPeer mock implementation of GroupAddPeer from server.AccountManager interface
func (am *MockAccountManager) GroupAddPeer(accountID, groupID, peerID string) error {
	if am.GroupAddPeerFunc != nil {
		return am.GroupAddPeerFunc(accountID, groupID, peerID)
	}
	return status.Errorf(codes.Unimplemented, "method GroupAddPeer is not implemented")
}

// GroupDeletePeer mock implementation of GroupDeletePeer from server.AccountManager interface
func (am *MockAccountManager) GroupDeletePeer(accountID, groupID, peerID string) error {
	if am.GroupDeletePeerFunc != nil {
		return am.GroupDeletePeerFunc(accountID, groupID, peerID)
	}
	return status.Errorf(codes.Unimplemented, "method GroupDeletePeer is not implemented")
}

// DeleteRule mock implementation of DeleteRule from server.AccountManager interface
func (am *MockAccountManager) DeleteRule(accountID, ruleID, userID string) error {
	if am.DeleteRuleFunc != nil {
		return am.DeleteRuleFunc(accountID, ruleID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteRule is not implemented")
}

// GetPolicy mock implementation of GetPolicy from server.AccountManager interface
func (am *MockAccountManager) GetPolicy(accountID, policyID, userID string) (*server.Policy, error) {
	if am.GetPolicyFunc != nil {
		return am.GetPolicyFunc(accountID, policyID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPolicy is not implemented")
}

// SavePolicy mock implementation of SavePolicy from server.AccountManager interface
func (am *MockAccountManager) SavePolicy(accountID, userID string, policy *server.Policy) error {
	if am.SavePolicyFunc != nil {
		return am.SavePolicyFunc(accountID, userID, policy)
	}
	return status.Errorf(codes.Unimplemented, "method SavePolicy is not implemented")
}

// DeletePolicy mock implementation of DeletePolicy from server.AccountManager interface
func (am *MockAccountManager) DeletePolicy(accountID, policyID, userID string) error {
	if am.DeletePolicyFunc != nil {
		return am.DeletePolicyFunc(accountID, policyID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeletePolicy is not implemented")
}

// ListPolicies mock implementation of ListPolicies from server.AccountManager interface
func (am *MockAccountManager) ListPolicies(accountID, userID string) ([]*server.Policy, error) {
	if am.ListPoliciesFunc != nil {
		return am.ListPoliciesFunc(accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListPolicies is not implemented")
}

// UpdatePeerMeta mock implementation of UpdatePeerMeta from server.AccountManager interface
func (am *MockAccountManager) UpdatePeerMeta(peerID string, meta nbpeer.PeerSystemMeta) error {
	if am.UpdatePeerMetaFunc != nil {
		return am.UpdatePeerMetaFunc(peerID, meta)
	}
	return status.Errorf(codes.Unimplemented, "method UpdatePeerMeta is not implemented")
}

// GetUser mock implementation of GetUser from server.AccountManager interface
func (am *MockAccountManager) GetUser(claims jwtclaims.AuthorizationClaims) (*server.User, error) {
	if am.GetUserFunc != nil {
		return am.GetUserFunc(claims)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetUser is not implemented")
}

func (am *MockAccountManager) ListUsers(accountID string) ([]*server.User, error) {
	if am.ListUsersFunc != nil {
		return am.ListUsersFunc(accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListUsers is not implemented")
}

// UpdatePeerSSHKey mocks UpdatePeerSSHKey function of the account manager
func (am *MockAccountManager) UpdatePeerSSHKey(peerID string, sshKey string) error {
	if am.UpdatePeerSSHKeyFunc != nil {
		return am.UpdatePeerSSHKeyFunc(peerID, sshKey)
	}
	return status.Errorf(codes.Unimplemented, "method UpdatePeerSSHKey is not implemented")
}

// UpdatePeer mocks UpdatePeerFunc function of the account manager
func (am *MockAccountManager) UpdatePeer(accountID, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, error) {
	if am.UpdatePeerFunc != nil {
		return am.UpdatePeerFunc(accountID, userID, peer)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePeer is not implemented")
}

// CreateRoute mock implementation of CreateRoute from server.AccountManager interface
func (am *MockAccountManager) CreateRoute(accountID, prefix, peerID string, peerGroupIDs []string, description string, netID route.NetID, masquerade bool, metric int, groups []string, enabled bool, userID string) (*route.Route, error) {
	if am.CreateRouteFunc != nil {
		return am.CreateRouteFunc(accountID, prefix, peerID, peerGroupIDs, description, netID, masquerade, metric, groups, enabled, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateRoute is not implemented")
}

// GetRoute mock implementation of GetRoute from server.AccountManager interface
func (am *MockAccountManager) GetRoute(accountID string, routeID route.ID, userID string) (*route.Route, error) {
	if am.GetRouteFunc != nil {
		return am.GetRouteFunc(accountID, routeID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetRoute is not implemented")
}

// SaveRoute mock implementation of SaveRoute from server.AccountManager interface
func (am *MockAccountManager) SaveRoute(accountID string, userID string, route *route.Route) error {
	if am.SaveRouteFunc != nil {
		return am.SaveRouteFunc(accountID, userID, route)
	}
	return status.Errorf(codes.Unimplemented, "method SaveRoute is not implemented")
}

// DeleteRoute mock implementation of DeleteRoute from server.AccountManager interface
func (am *MockAccountManager) DeleteRoute(accountID string, routeID route.ID, userID string) error {
	if am.DeleteRouteFunc != nil {
		return am.DeleteRouteFunc(accountID, routeID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteRoute is not implemented")
}

// ListRoutes mock implementation of ListRoutes from server.AccountManager interface
func (am *MockAccountManager) ListRoutes(accountID, userID string) ([]*route.Route, error) {
	if am.ListRoutesFunc != nil {
		return am.ListRoutesFunc(accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListRoutes is not implemented")
}

// SaveSetupKey mocks SaveSetupKey of the AccountManager interface
func (am *MockAccountManager) SaveSetupKey(accountID string, key *server.SetupKey, userID string) (*server.SetupKey, error) {
	if am.SaveSetupKeyFunc != nil {
		return am.SaveSetupKeyFunc(accountID, key, userID)
	}

	return nil, status.Errorf(codes.Unimplemented, "method SaveSetupKey is not implemented")
}

// GetSetupKey mocks GetSetupKey of the AccountManager interface
func (am *MockAccountManager) GetSetupKey(accountID, userID, keyID string) (*server.SetupKey, error) {
	if am.GetSetupKeyFunc != nil {
		return am.GetSetupKeyFunc(accountID, userID, keyID)
	}

	return nil, status.Errorf(codes.Unimplemented, "method GetSetupKey is not implemented")
}

// ListSetupKeys mocks ListSetupKeys of the AccountManager interface
func (am *MockAccountManager) ListSetupKeys(accountID, userID string) ([]*server.SetupKey, error) {
	if am.ListSetupKeysFunc != nil {
		return am.ListSetupKeysFunc(accountID, userID)
	}

	return nil, status.Errorf(codes.Unimplemented, "method ListSetupKeys is not implemented")
}

// SaveUser mocks SaveUser of the AccountManager interface
func (am *MockAccountManager) SaveUser(accountID, userID string, user *server.User) (*server.UserInfo, error) {
	if am.SaveUserFunc != nil {
		return am.SaveUserFunc(accountID, userID, user)
	}
	return nil, status.Errorf(codes.Unimplemented, "method SaveUser is not implemented")
}

// SaveOrAddUser mocks SaveOrAddUser of the AccountManager interface
func (am *MockAccountManager) SaveOrAddUser(accountID, userID string, user *server.User, addIfNotExists bool) (*server.UserInfo, error) {
	if am.SaveOrAddUserFunc != nil {
		return am.SaveOrAddUserFunc(accountID, userID, user, addIfNotExists)
	}
	return nil, status.Errorf(codes.Unimplemented, "method SaveOrAddUser is not implemented")
}

// DeleteUser mocks DeleteUser of the AccountManager interface
func (am *MockAccountManager) DeleteUser(accountID string, initiatorUserID string, targetUserID string) error {
	if am.DeleteUserFunc != nil {
		return am.DeleteUserFunc(accountID, initiatorUserID, targetUserID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteUser is not implemented")
}

func (am *MockAccountManager) InviteUser(accountID string, initiatorUserID string, targetUserID string) error {
	if am.InviteUserFunc != nil {
		return am.InviteUserFunc(accountID, initiatorUserID, targetUserID)
	}
	return status.Errorf(codes.Unimplemented, "method InviteUser is not implemented")
}

// GetNameServerGroup mocks GetNameServerGroup of the AccountManager interface
func (am *MockAccountManager) GetNameServerGroup(accountID, userID, nsGroupID string) (*nbdns.NameServerGroup, error) {
	if am.GetNameServerGroupFunc != nil {
		return am.GetNameServerGroupFunc(accountID, userID, nsGroupID)
	}
	return nil, nil
}

// CreateNameServerGroup mocks CreateNameServerGroup of the AccountManager interface
func (am *MockAccountManager) CreateNameServerGroup(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string, searchDomainsEnabled bool) (*nbdns.NameServerGroup, error) {
	if am.CreateNameServerGroupFunc != nil {
		return am.CreateNameServerGroupFunc(accountID, name, description, nameServerList, groups, primary, domains, enabled, userID, searchDomainsEnabled)
	}
	return nil, nil
}

// SaveNameServerGroup mocks SaveNameServerGroup of the AccountManager interface
func (am *MockAccountManager) SaveNameServerGroup(accountID, userID string, nsGroupToSave *nbdns.NameServerGroup) error {
	if am.SaveNameServerGroupFunc != nil {
		return am.SaveNameServerGroupFunc(accountID, userID, nsGroupToSave)
	}
	return nil
}

// DeleteNameServerGroup mocks DeleteNameServerGroup of the AccountManager interface
func (am *MockAccountManager) DeleteNameServerGroup(accountID, nsGroupID, userID string) error {
	if am.DeleteNameServerGroupFunc != nil {
		return am.DeleteNameServerGroupFunc(accountID, nsGroupID, userID)
	}
	return nil
}

// ListNameServerGroups mocks ListNameServerGroups of the AccountManager interface
func (am *MockAccountManager) ListNameServerGroups(accountID string, userID string) ([]*nbdns.NameServerGroup, error) {
	if am.ListNameServerGroupsFunc != nil {
		return am.ListNameServerGroupsFunc(accountID, userID)
	}
	return nil, nil
}

// CreateUser mocks CreateUser of the AccountManager interface
func (am *MockAccountManager) CreateUser(accountID, userID string, invite *server.UserInfo) (*server.UserInfo, error) {
	if am.CreateUserFunc != nil {
		return am.CreateUserFunc(accountID, userID, invite)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateUser is not implemented")
}

// GetAccountFromToken mocks GetAccountFromToken of the AccountManager interface
func (am *MockAccountManager) GetAccountFromToken(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User,
	error,
) {
	if am.GetAccountFromTokenFunc != nil {
		return am.GetAccountFromTokenFunc(claims)
	}
	return nil, nil, status.Errorf(codes.Unimplemented, "method GetAccountFromToken is not implemented")
}

func (am *MockAccountManager) CheckUserAccessByJWTGroups(claims jwtclaims.AuthorizationClaims) error {
	if am.CheckUserAccessByJWTGroupsFunc != nil {
		return am.CheckUserAccessByJWTGroupsFunc(claims)
	}
	return status.Errorf(codes.Unimplemented, "method CheckUserAccessByJWTGroups is not implemented")
}

// GetPeers mocks GetPeers of the AccountManager interface
func (am *MockAccountManager) GetPeers(accountID, userID string) ([]*nbpeer.Peer, error) {
	if am.GetPeersFunc != nil {
		return am.GetPeersFunc(accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeers is not implemented")
}

// GetDNSDomain mocks GetDNSDomain of the AccountManager interface
func (am *MockAccountManager) GetDNSDomain() string {
	if am.GetDNSDomainFunc != nil {
		return am.GetDNSDomainFunc()
	}
	return ""
}

// GetEvents mocks GetEvents of the AccountManager interface
func (am *MockAccountManager) GetEvents(accountID, userID string) ([]*activity.Event, error) {
	if am.GetEventsFunc != nil {
		return am.GetEventsFunc(accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetEvents is not implemented")
}

// GetDNSSettings mocks GetDNSSettings of the AccountManager interface
func (am *MockAccountManager) GetDNSSettings(accountID string, userID string) (*server.DNSSettings, error) {
	if am.GetDNSSettingsFunc != nil {
		return am.GetDNSSettingsFunc(accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetDNSSettings is not implemented")
}

// SaveDNSSettings mocks SaveDNSSettings of the AccountManager interface
func (am *MockAccountManager) SaveDNSSettings(accountID string, userID string, dnsSettingsToSave *server.DNSSettings) error {
	if am.SaveDNSSettingsFunc != nil {
		return am.SaveDNSSettingsFunc(accountID, userID, dnsSettingsToSave)
	}
	return status.Errorf(codes.Unimplemented, "method SaveDNSSettings is not implemented")
}

// GetPeer mocks GetPeer of the AccountManager interface
func (am *MockAccountManager) GetPeer(accountID, peerID, userID string) (*nbpeer.Peer, error) {
	if am.GetPeerFunc != nil {
		return am.GetPeerFunc(accountID, peerID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeer is not implemented")
}

// UpdateAccountSettings mocks UpdateAccountSettings of the AccountManager interface
func (am *MockAccountManager) UpdateAccountSettings(accountID, userID string, newSettings *server.Settings) (*server.Account, error) {
	if am.UpdateAccountSettingsFunc != nil {
		return am.UpdateAccountSettingsFunc(accountID, userID, newSettings)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAccountSettings is not implemented")
}

// LoginPeer mocks LoginPeer of the AccountManager interface
func (am *MockAccountManager) LoginPeer(login server.PeerLogin) (*nbpeer.Peer, *server.NetworkMap, error) {
	if am.LoginPeerFunc != nil {
		return am.LoginPeerFunc(login)
	}
	return nil, nil, status.Errorf(codes.Unimplemented, "method LoginPeer is not implemented")
}

// SyncPeer mocks SyncPeer of the AccountManager interface
func (am *MockAccountManager) SyncPeer(sync server.PeerSync, account *server.Account) (*nbpeer.Peer, *server.NetworkMap, error) {
	if am.SyncPeerFunc != nil {
		return am.SyncPeerFunc(sync, account)
	}
	return nil, nil, status.Errorf(codes.Unimplemented, "method SyncPeer is not implemented")
}

// GetAllConnectedPeers mocks GetAllConnectedPeers of the AccountManager interface
func (am *MockAccountManager) GetAllConnectedPeers() (map[string]struct{}, error) {
	if am.GetAllConnectedPeersFunc != nil {
		return am.GetAllConnectedPeersFunc()
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAllConnectedPeers is not implemented")
}

// HasConnectedChannel mocks HasConnectedChannel of the AccountManager interface
func (am *MockAccountManager) HasConnectedChannel(peerID string) bool {
	if am.HasConnectedChannelFunc != nil {
		return am.HasConnectedChannelFunc(peerID)
	}
	return false
}

// StoreEvent mocks StoreEvent of the AccountManager interface
func (am *MockAccountManager) StoreEvent(initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
	if am.StoreEventFunc != nil {
		am.StoreEventFunc(initiatorID, targetID, accountID, activityID, meta)
	}
}

// GetExternalCacheManager mocks GetExternalCacheManager of the AccountManager interface
func (am *MockAccountManager) GetExternalCacheManager() server.ExternalCacheManager {
	if am.GetExternalCacheManagerFunc() != nil {
		return am.GetExternalCacheManagerFunc()
	}
	return nil
}

// GetPostureChecks mocks GetPostureChecks of the AccountManager interface
func (am *MockAccountManager) GetPostureChecks(accountID, postureChecksID, userID string) (*posture.Checks, error) {
	if am.GetPostureChecksFunc != nil {
		return am.GetPostureChecksFunc(accountID, postureChecksID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPostureChecks is not implemented")

}

// SavePostureChecks mocks SavePostureChecks of the AccountManager interface
func (am *MockAccountManager) SavePostureChecks(accountID, userID string, postureChecks *posture.Checks) error {
	if am.SavePostureChecksFunc != nil {
		return am.SavePostureChecksFunc(accountID, userID, postureChecks)
	}
	return status.Errorf(codes.Unimplemented, "method SavePostureChecks is not implemented")
}

// DeletePostureChecks mocks DeletePostureChecks of the AccountManager interface
func (am *MockAccountManager) DeletePostureChecks(accountID, postureChecksID, userID string) error {
	if am.DeletePostureChecksFunc != nil {
		return am.DeletePostureChecksFunc(accountID, postureChecksID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeletePostureChecks is not implemented")

}

// ListPostureChecks mocks ListPostureChecks of the AccountManager interface
func (am *MockAccountManager) ListPostureChecks(accountID, userID string) ([]*posture.Checks, error) {
	if am.ListPostureChecksFunc != nil {
		return am.ListPostureChecksFunc(accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListPostureChecks is not implemented")
}

// GetIdpManager mocks GetIdpManager of the AccountManager interface
func (am *MockAccountManager) GetIdpManager() idp.Manager {
	if am.GetIdpManagerFunc != nil {
		return am.GetIdpManagerFunc()
	}
	return nil
}

// UpdateIntegratedValidatorGroups mocks UpdateIntegratedApprovalGroups of the AccountManager interface
func (am *MockAccountManager) UpdateIntegratedValidatorGroups(accountID string, userID string, groups []string) error {
	if am.UpdateIntegratedValidatorGroupsFunc != nil {
		return am.UpdateIntegratedValidatorGroupsFunc(accountID, userID, groups)
	}
	return status.Errorf(codes.Unimplemented, "method UpdateIntegratedValidatorGroups is not implemented")
}

// GroupValidation mocks GroupValidation of the AccountManager interface
func (am *MockAccountManager) GroupValidation(accountId string, groups []string) (bool, error) {
	if am.GroupValidationFunc != nil {
		return am.GroupValidationFunc(accountId, groups)
	}
	return false, status.Errorf(codes.Unimplemented, "method GroupValidation is not implemented")
}

// FindExistingPostureCheck mocks FindExistingPostureCheck of the AccountManager interface
func (am *MockAccountManager) FindExistingPostureCheck(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error) {
	if am.FindExistingPostureCheckFunc != nil {
		return am.FindExistingPostureCheckFunc(accountID, checks)
	}
	return nil, status.Errorf(codes.Unimplemented, "method FindExistingPostureCheck is not implemented")
}
