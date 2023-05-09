package mock_server

import (
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/route"
)

type MockAccountManager struct {
	GetOrCreateAccountByUserFunc func(userId, domain string) (*server.Account, error)
	CreateSetupKeyFunc           func(accountId string, keyName string, keyType server.SetupKeyType,
		expiresIn time.Duration, autoGroups []string, usageLimit int, userID string) (*server.SetupKey, error)
	GetSetupKeyFunc                 func(accountID, userID, keyID string) (*server.SetupKey, error)
	GetAccountByUserOrAccountIdFunc func(userId, accountId, domain string) (*server.Account, error)
	GetUserFunc                     func(claims jwtclaims.AuthorizationClaims) (*server.User, error)
	AccountExistsFunc               func(accountId string) (*bool, error)
	GetPeerByKeyFunc                func(peerKey string) (*server.Peer, error)
	GetPeersFunc                    func(accountID, userID string) ([]*server.Peer, error)
	MarkPeerConnectedFunc           func(peerKey string, connected bool) error
	DeletePeerFunc                  func(accountID, peerKey, userID string) (*server.Peer, error)
	GetPeerByIPFunc                 func(accountId string, peerIP string) (*server.Peer, error)
	GetNetworkMapFunc               func(peerKey string) (*server.NetworkMap, error)
	GetPeerNetworkFunc              func(peerKey string) (*server.Network, error)
	AddPeerFunc                     func(setupKey string, userId string, peer *server.Peer) (*server.Peer, *server.NetworkMap, error)
	GetGroupFunc                    func(accountID, groupID string) (*server.Group, error)
	SaveGroupFunc                   func(accountID, userID string, group *server.Group) error
	UpdateGroupFunc                 func(accountID string, groupID string, operations []server.GroupUpdateOperation) (*server.Group, error)
	DeleteGroupFunc                 func(accountID, groupID string) error
	ListGroupsFunc                  func(accountID string) ([]*server.Group, error)
	GroupAddPeerFunc                func(accountID, groupID, peerKey string) error
	GroupDeletePeerFunc             func(accountID, groupID, peerKey string) error
	GroupListPeersFunc              func(accountID, groupID string) ([]*server.Peer, error)
	GetRuleFunc                     func(accountID, ruleID, userID string) (*server.Rule, error)
	SaveRuleFunc                    func(accountID, userID string, rule *server.Rule) error
	DeleteRuleFunc                  func(accountID, ruleID, userID string) error
	ListRulesFunc                   func(accountID, userID string) ([]*server.Rule, error)
	GetPolicyFunc                   func(accountID, policyID, userID string) (*server.Policy, error)
	SavePolicyFunc                  func(accountID, userID string, policy *server.Policy) error
	DeletePolicyFunc                func(accountID, policyID, userID string) error
	ListPoliciesFunc                func(accountID, userID string) ([]*server.Policy, error)
	GetUsersFromAccountFunc         func(accountID, userID string) ([]*server.UserInfo, error)
	GetAccountFromPATFunc           func(pat string) (*server.Account, *server.User, *server.PersonalAccessToken, error)
	MarkPATUsedFunc                 func(pat string) error
	UpdatePeerMetaFunc              func(peerID string, meta server.PeerSystemMeta) error
	UpdatePeerSSHKeyFunc            func(peerID string, sshKey string) error
	UpdatePeerFunc                  func(accountID, userID string, peer *server.Peer) (*server.Peer, error)
	CreateRouteFunc                 func(accountID string, prefix, peer, description, netID string, masquerade bool, metric int, groups []string, enabled bool, userID string) (*route.Route, error)
	GetRouteFunc                    func(accountID, routeID, userID string) (*route.Route, error)
	SaveRouteFunc                   func(accountID, userID string, route *route.Route) error
	UpdateRouteFunc                 func(accountID string, routeID string, operations []server.RouteUpdateOperation) (*route.Route, error)
	DeleteRouteFunc                 func(accountID, routeID, userID string) error
	ListRoutesFunc                  func(accountID, userID string) ([]*route.Route, error)
	SaveSetupKeyFunc                func(accountID string, key *server.SetupKey, userID string) (*server.SetupKey, error)
	ListSetupKeysFunc               func(accountID, userID string) ([]*server.SetupKey, error)
	SaveUserFunc                    func(accountID, userID string, user *server.User) (*server.UserInfo, error)
	DeleteUserFunc                  func(accountID string, executingUserID string, targetUserID string) error
	CreatePATFunc                   func(accountID string, executingUserID string, targetUserId string, tokenName string, expiresIn int) (*server.PersonalAccessTokenGenerated, error)
	DeletePATFunc                   func(accountID string, executingUserID string, targetUserId string, tokenID string) error
	GetPATFunc                      func(accountID string, executingUserID string, targetUserId string, tokenID string) (*server.PersonalAccessToken, error)
	GetAllPATsFunc                  func(accountID string, executingUserID string, targetUserId string) ([]*server.PersonalAccessToken, error)
	GetNameServerGroupFunc          func(accountID, nsGroupID string) (*nbdns.NameServerGroup, error)
	CreateNameServerGroupFunc       func(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string) (*nbdns.NameServerGroup, error)
	SaveNameServerGroupFunc         func(accountID, userID string, nsGroupToSave *nbdns.NameServerGroup) error
	UpdateNameServerGroupFunc       func(accountID, nsGroupID, userID string, operations []server.NameServerGroupUpdateOperation) (*nbdns.NameServerGroup, error)
	DeleteNameServerGroupFunc       func(accountID, nsGroupID, userID string) error
	ListNameServerGroupsFunc        func(accountID string) ([]*nbdns.NameServerGroup, error)
	CreateUserFunc                  func(accountID, userID string, key *server.UserInfo) (*server.UserInfo, error)
	GetAccountFromTokenFunc         func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error)
	GetDNSDomainFunc                func() string
	GetEventsFunc                   func(accountID, userID string) ([]*activity.Event, error)
	GetDNSSettingsFunc              func(accountID, userID string) (*server.DNSSettings, error)
	SaveDNSSettingsFunc             func(accountID, userID string, dnsSettingsToSave *server.DNSSettings) error
	GetPeerFunc                     func(accountID, peerID, userID string) (*server.Peer, error)
	UpdateAccountSettingsFunc       func(accountID, userID string, newSettings *server.Settings) (*server.Account, error)
	LoginPeerFunc                   func(login server.PeerLogin) (*server.Peer, *server.NetworkMap, error)
	SyncPeerFunc                    func(sync server.PeerSync) (*server.Peer, *server.NetworkMap, error)
}

// GetUsersFromAccount mock implementation of GetUsersFromAccount from server.AccountManager interface
func (am *MockAccountManager) GetUsersFromAccount(accountID string, userID string) ([]*server.UserInfo, error) {
	if am.GetUsersFromAccountFunc != nil {
		return am.GetUsersFromAccountFunc(accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetUsersFromAccount is not implemented")
}

// DeletePeer mock implementation of DeletePeer from server.AccountManager interface
func (am *MockAccountManager) DeletePeer(accountID, peerID, userID string) (*server.Peer, error) {
	if am.DeletePeerFunc != nil {
		return am.DeletePeerFunc(accountID, peerID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method DeletePeer is not implemented")
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
) (*server.SetupKey, error) {
	if am.CreateSetupKeyFunc != nil {
		return am.CreateSetupKeyFunc(accountID, keyName, keyType, expiresIn, autoGroups, usageLimit, userID)
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

// AccountExists mock implementation of AccountExists from server.AccountManager interface
func (am *MockAccountManager) AccountExists(accountId string) (*bool, error) {
	if am.AccountExistsFunc != nil {
		return am.AccountExistsFunc(accountId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method AccountExists is not implemented")
}

// GetPeerByKey mocks implementation of GetPeerByKey from server.AccountManager interface
func (am *MockAccountManager) GetPeerByKey(peerKey string) (*server.Peer, error) {
	if am.GetPeerByKeyFunc != nil {
		return am.GetPeerByKeyFunc(peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeerByKey is not implemented")
}

// MarkPeerConnected mock implementation of MarkPeerConnected from server.AccountManager interface
func (am *MockAccountManager) MarkPeerConnected(peerKey string, connected bool) error {
	if am.MarkPeerConnectedFunc != nil {
		return am.MarkPeerConnectedFunc(peerKey, connected)
	}
	return status.Errorf(codes.Unimplemented, "method MarkPeerConnected is not implemented")
}

// GetPeerByIP mock implementation of GetPeerByIP from server.AccountManager interface
func (am *MockAccountManager) GetPeerByIP(accountId string, peerIP string) (*server.Peer, error) {
	if am.GetPeerByIPFunc != nil {
		return am.GetPeerByIPFunc(accountId, peerIP)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeerByIP is not implemented")
}

// GetAccountFromPAT mock implementation of GetAccountFromPAT from server.AccountManager interface
func (am *MockAccountManager) GetAccountFromPAT(pat string) (*server.Account, *server.User, *server.PersonalAccessToken, error) {
	if am.GetAccountFromPATFunc != nil {
		return am.GetAccountFromPATFunc(pat)
	}
	return nil, nil, nil, status.Errorf(codes.Unimplemented, "method GetAccountFromPAT is not implemented")
}

// MarkPATUsed mock implementation of MarkPATUsed from server.AccountManager interface
func (am *MockAccountManager) MarkPATUsed(pat string) error {
	if am.MarkPATUsedFunc != nil {
		return am.MarkPATUsedFunc(pat)
	}
	return status.Errorf(codes.Unimplemented, "method MarkPATUsed is not implemented")
}

// CreatePAT mock implementation of GetPAT from server.AccountManager interface
func (am *MockAccountManager) CreatePAT(accountID string, executingUserID string, targetUserID string, name string, expiresIn int) (*server.PersonalAccessTokenGenerated, error) {
	if am.CreatePATFunc != nil {
		return am.CreatePATFunc(accountID, executingUserID, targetUserID, name, expiresIn)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreatePAT is not implemented")
}

// DeletePAT mock implementation of DeletePAT from server.AccountManager interface
func (am *MockAccountManager) DeletePAT(accountID string, executingUserID string, targetUserID string, tokenID string) error {
	if am.DeletePATFunc != nil {
		return am.DeletePATFunc(accountID, executingUserID, targetUserID, tokenID)
	}
	return status.Errorf(codes.Unimplemented, "method DeletePAT is not implemented")
}

// GetPAT mock implementation of GetPAT from server.AccountManager interface
func (am *MockAccountManager) GetPAT(accountID string, executingUserID string, targetUserID string, tokenID string) (*server.PersonalAccessToken, error) {
	if am.GetPATFunc != nil {
		return am.GetPATFunc(accountID, executingUserID, targetUserID, tokenID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPAT is not implemented")
}

// GetAllPATs mock implementation of GetAllPATs from server.AccountManager interface
func (am *MockAccountManager) GetAllPATs(accountID string, executingUserID string, targetUserID string) ([]*server.PersonalAccessToken, error) {
	if am.GetAllPATsFunc != nil {
		return am.GetAllPATsFunc(accountID, executingUserID, targetUserID)
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
	peer *server.Peer,
) (*server.Peer, *server.NetworkMap, error) {
	if am.AddPeerFunc != nil {
		return am.AddPeerFunc(setupKey, userId, peer)
	}
	return nil, nil, status.Errorf(codes.Unimplemented, "method AddPeer is not implemented")
}

// GetGroup mock implementation of GetGroup from server.AccountManager interface
func (am *MockAccountManager) GetGroup(accountID, groupID string) (*server.Group, error) {
	if am.GetGroupFunc != nil {
		return am.GetGroupFunc(accountID, groupID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetGroup is not implemented")
}

// SaveGroup mock implementation of SaveGroup from server.AccountManager interface
func (am *MockAccountManager) SaveGroup(accountID, userID string, group *server.Group) error {
	if am.SaveGroupFunc != nil {
		return am.SaveGroupFunc(accountID, userID, group)
	}
	return status.Errorf(codes.Unimplemented, "method SaveGroup is not implemented")
}

// UpdateGroup mock implementation of UpdateGroup from server.AccountManager interface
func (am *MockAccountManager) UpdateGroup(accountID string, groupID string, operations []server.GroupUpdateOperation) (*server.Group, error) {
	if am.UpdateGroupFunc != nil {
		return am.UpdateGroupFunc(accountID, groupID, operations)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdateGroup not implemented")
}

// DeleteGroup mock implementation of DeleteGroup from server.AccountManager interface
func (am *MockAccountManager) DeleteGroup(accountID, groupID string) error {
	if am.DeleteGroupFunc != nil {
		return am.DeleteGroupFunc(accountID, groupID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteGroup is not implemented")
}

// ListGroups mock implementation of ListGroups from server.AccountManager interface
func (am *MockAccountManager) ListGroups(accountID string) ([]*server.Group, error) {
	if am.ListGroupsFunc != nil {
		return am.ListGroupsFunc(accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListGroups is not implemented")
}

// GroupAddPeer mock implementation of GroupAddPeer from server.AccountManager interface
func (am *MockAccountManager) GroupAddPeer(accountID, groupID, peerKey string) error {
	if am.GroupAddPeerFunc != nil {
		return am.GroupAddPeerFunc(accountID, groupID, peerKey)
	}
	return status.Errorf(codes.Unimplemented, "method GroupAddPeer is not implemented")
}

// GroupDeletePeer mock implementation of GroupDeletePeer from server.AccountManager interface
func (am *MockAccountManager) GroupDeletePeer(accountID, groupID, peerKey string) error {
	if am.GroupDeletePeerFunc != nil {
		return am.GroupDeletePeerFunc(accountID, groupID, peerKey)
	}
	return status.Errorf(codes.Unimplemented, "method GroupDeletePeer is not implemented")
}

// GroupListPeers mock implementation of GroupListPeers from server.AccountManager interface
func (am *MockAccountManager) GroupListPeers(accountID, groupID string) ([]*server.Peer, error) {
	if am.GroupListPeersFunc != nil {
		return am.GroupListPeersFunc(accountID, groupID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GroupListPeers is not implemented")
}

// GetRule mock implementation of GetRule from server.AccountManager interface
func (am *MockAccountManager) GetRule(accountID, ruleID, userID string) (*server.Rule, error) {
	if am.GetRuleFunc != nil {
		return am.GetRuleFunc(accountID, ruleID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetRule is not implemented")
}

// SaveRule mock implementation of SaveRule from server.AccountManager interface
func (am *MockAccountManager) SaveRule(accountID, userID string, rule *server.Rule) error {
	if am.SaveRuleFunc != nil {
		return am.SaveRuleFunc(accountID, userID, rule)
	}
	return status.Errorf(codes.Unimplemented, "method SaveRule is not implemented")
}

// DeleteRule mock implementation of DeleteRule from server.AccountManager interface
func (am *MockAccountManager) DeleteRule(accountID, ruleID, userID string) error {
	if am.DeleteRuleFunc != nil {
		return am.DeleteRuleFunc(accountID, ruleID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteRule is not implemented")
}

// ListRules mock implementation of ListRules from server.AccountManager interface
func (am *MockAccountManager) ListRules(accountID, userID string) ([]*server.Rule, error) {
	if am.ListRulesFunc != nil {
		return am.ListRulesFunc(accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListRules is not implemented")
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
func (am *MockAccountManager) UpdatePeerMeta(peerID string, meta server.PeerSystemMeta) error {
	if am.UpdatePeerMetaFunc != nil {
		return am.UpdatePeerMetaFunc(peerID, meta)
	}
	return status.Errorf(codes.Unimplemented, "method UpdatePeerMetaFunc is not implemented")
}

// GetUser mock implementation of GetUser from server.AccountManager interface
func (am *MockAccountManager) GetUser(claims jwtclaims.AuthorizationClaims) (*server.User, error) {
	if am.GetUserFunc != nil {
		return am.GetUserFunc(claims)
	}
	return nil, status.Errorf(codes.Unimplemented, "method IsUserGetUserAdmin is not implemented")
}

// UpdatePeerSSHKey mocks UpdatePeerSSHKey function of the account manager
func (am *MockAccountManager) UpdatePeerSSHKey(peerID string, sshKey string) error {
	if am.UpdatePeerSSHKeyFunc != nil {
		return am.UpdatePeerSSHKeyFunc(peerID, sshKey)
	}
	return status.Errorf(codes.Unimplemented, "method UpdatePeerSSHKey is is not implemented")
}

// UpdatePeer mocks UpdatePeerFunc function of the account manager
func (am *MockAccountManager) UpdatePeer(accountID, userID string, peer *server.Peer) (*server.Peer, error) {
	if am.UpdatePeerFunc != nil {
		return am.UpdatePeerFunc(accountID, userID, peer)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePeerFunc is is not implemented")
}

// CreateRoute mock implementation of CreateRoute from server.AccountManager interface
func (am *MockAccountManager) CreateRoute(accountID string, network, peerID, description, netID string, masquerade bool, metric int, groups []string, enabled bool, userID string) (*route.Route, error) {
	if am.CreateRouteFunc != nil {
		return am.CreateRouteFunc(accountID, network, peerID, description, netID, masquerade, metric, groups, enabled, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateRoute is not implemented")
}

// GetRoute mock implementation of GetRoute from server.AccountManager interface
func (am *MockAccountManager) GetRoute(accountID, routeID, userID string) (*route.Route, error) {
	if am.GetRouteFunc != nil {
		return am.GetRouteFunc(accountID, routeID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetRoute is not implemented")
}

// SaveRoute mock implementation of SaveRoute from server.AccountManager interface
func (am *MockAccountManager) SaveRoute(accountID, userID string, route *route.Route) error {
	if am.SaveRouteFunc != nil {
		return am.SaveRouteFunc(accountID, userID, route)
	}
	return status.Errorf(codes.Unimplemented, "method SaveRoute is not implemented")
}

// UpdateRoute mock implementation of UpdateRoute from server.AccountManager interface
func (am *MockAccountManager) UpdateRoute(accountID, ruleID string, operations []server.RouteUpdateOperation) (*route.Route, error) {
	if am.UpdateRouteFunc != nil {
		return am.UpdateRouteFunc(accountID, ruleID, operations)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdateRoute not implemented")
}

// DeleteRoute mock implementation of DeleteRoute from server.AccountManager interface
func (am *MockAccountManager) DeleteRoute(accountID, routeID, userID string) error {
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

// DeleteUser mocks DeleteUser of the AccountManager interface
func (am *MockAccountManager) DeleteUser(accountID string, executingUserID string, targetUserID string) error {
	if am.DeleteUserFunc != nil {
		return am.DeleteUserFunc(accountID, executingUserID, targetUserID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteUser is not implemented")
}

// GetNameServerGroup mocks GetNameServerGroup of the AccountManager interface
func (am *MockAccountManager) GetNameServerGroup(accountID, nsGroupID string) (*nbdns.NameServerGroup, error) {
	if am.GetNameServerGroupFunc != nil {
		return am.GetNameServerGroupFunc(accountID, nsGroupID)
	}
	return nil, nil
}

// CreateNameServerGroup mocks CreateNameServerGroup of the AccountManager interface
func (am *MockAccountManager) CreateNameServerGroup(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string) (*nbdns.NameServerGroup, error) {
	if am.CreateNameServerGroupFunc != nil {
		return am.CreateNameServerGroupFunc(accountID, name, description, nameServerList, groups, primary, domains, enabled, userID)
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

// UpdateNameServerGroup mocks UpdateNameServerGroup of the AccountManager interface
func (am *MockAccountManager) UpdateNameServerGroup(accountID, nsGroupID, userID string, operations []server.NameServerGroupUpdateOperation) (*nbdns.NameServerGroup, error) {
	if am.UpdateNameServerGroupFunc != nil {
		return am.UpdateNameServerGroupFunc(accountID, nsGroupID, userID, operations)
	}
	return nil, nil
}

// DeleteNameServerGroup mocks DeleteNameServerGroup of the AccountManager interface
func (am *MockAccountManager) DeleteNameServerGroup(accountID, nsGroupID, userID string) error {
	if am.DeleteNameServerGroupFunc != nil {
		return am.DeleteNameServerGroupFunc(accountID, nsGroupID, userID)
	}
	return nil
}

// ListNameServerGroups mocks ListNameServerGroups of the AccountManager interface
func (am *MockAccountManager) ListNameServerGroups(accountID string) ([]*nbdns.NameServerGroup, error) {
	if am.ListNameServerGroupsFunc != nil {
		return am.ListNameServerGroupsFunc(accountID)
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

// GetPeers mocks GetPeers of the AccountManager interface
func (am *MockAccountManager) GetPeers(accountID, userID string) ([]*server.Peer, error) {
	if am.GetAccountFromTokenFunc != nil {
		return am.GetPeersFunc(accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAllPeers is not implemented")
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
	return nil, status.Errorf(codes.Unimplemented, "method GetAllEvents is not implemented")
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
func (am *MockAccountManager) GetPeer(accountID, peerID, userID string) (*server.Peer, error) {
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
func (am *MockAccountManager) LoginPeer(login server.PeerLogin) (*server.Peer, *server.NetworkMap, error) {
	if am.LoginPeerFunc != nil {
		return am.LoginPeerFunc(login)
	}
	return nil, nil, status.Errorf(codes.Unimplemented, "method LoginPeer is not implemented")
}

// SyncPeer mocks SyncPeer of the AccountManager interface
func (am *MockAccountManager) SyncPeer(sync server.PeerSync) (*server.Peer, *server.NetworkMap, error) {
	if am.SyncPeerFunc != nil {
		return am.SyncPeerFunc(sync)
	}
	return nil, nil, status.Errorf(codes.Unimplemented, "method SyncPeer is not implemented")
}
