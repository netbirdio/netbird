package mock_server

import (
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/route"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

type MockAccountManager struct {
	GetOrCreateAccountByUserFunc    func(userId, domain string) (*server.Account, error)
	GetAccountByUserFunc            func(userId string) (*server.Account, error)
	CreateSetupKeyFunc              func(accountId string, keyName string, keyType server.SetupKeyType, expiresIn time.Duration, autoGroups []string) (*server.SetupKey, error)
	GetSetupKeyFunc                 func(accountID, userID, keyID string) (*server.SetupKey, error)
	GetAccountByIdFunc              func(accountId string) (*server.Account, error)
	GetAccountByUserOrAccountIdFunc func(userId, accountId, domain string) (*server.Account, error)
	IsUserAdminFunc                 func(claims jwtclaims.AuthorizationClaims) (bool, error)
	AccountExistsFunc               func(accountId string) (*bool, error)
	GetPeerFunc                     func(peerKey string) (*server.Peer, error)
	MarkPeerConnectedFunc           func(peerKey string, connected bool) error
	RenamePeerFunc                  func(accountId string, peerKey string, newName string) (*server.Peer, error)
	DeletePeerFunc                  func(accountId string, peerKey string) (*server.Peer, error)
	GetPeerByIPFunc                 func(accountId string, peerIP string) (*server.Peer, error)
	GetNetworkMapFunc               func(peerKey string) (*server.NetworkMap, error)
	GetPeerNetworkFunc              func(peerKey string) (*server.Network, error)
	AddPeerFunc                     func(setupKey string, userId string, peer *server.Peer) (*server.Peer, error)
	GetGroupFunc                    func(accountID, groupID string) (*server.Group, error)
	SaveGroupFunc                   func(accountID string, group *server.Group) error
	UpdateGroupFunc                 func(accountID string, groupID string, operations []server.GroupUpdateOperation) (*server.Group, error)
	DeleteGroupFunc                 func(accountID, groupID string) error
	ListGroupsFunc                  func(accountID string) ([]*server.Group, error)
	GroupAddPeerFunc                func(accountID, groupID, peerKey string) error
	GroupDeletePeerFunc             func(accountID, groupID, peerKey string) error
	GroupListPeersFunc              func(accountID, groupID string) ([]*server.Peer, error)
	GetRuleFunc                     func(accountID, ruleID string) (*server.Rule, error)
	SaveRuleFunc                    func(accountID string, rule *server.Rule) error
	UpdateRuleFunc                  func(accountID string, ruleID string, operations []server.RuleUpdateOperation) (*server.Rule, error)
	DeleteRuleFunc                  func(accountID, ruleID string) error
	ListRulesFunc                   func(accountID string) ([]*server.Rule, error)
	GetUsersFromAccountFunc         func(accountID string) ([]*server.UserInfo, error)
	UpdatePeerMetaFunc              func(peerKey string, meta server.PeerSystemMeta) error
	UpdatePeerSSHKeyFunc            func(peerKey string, sshKey string) error
	UpdatePeerFunc                  func(accountID string, peer *server.Peer) (*server.Peer, error)
	CreateRouteFunc                 func(accountID string, prefix, peer, description, netID string, masquerade bool, metric int, enabled bool) (*route.Route, error)
	GetRouteFunc                    func(accountID, routeID string) (*route.Route, error)
	SaveRouteFunc                   func(accountID string, route *route.Route) error
	UpdateRouteFunc                 func(accountID string, routeID string, operations []server.RouteUpdateOperation) (*route.Route, error)
	DeleteRouteFunc                 func(accountID, routeID string) error
	ListRoutesFunc                  func(accountID string) ([]*route.Route, error)
	SaveSetupKeyFunc                func(accountID string, key *server.SetupKey) (*server.SetupKey, error)
	ListSetupKeysFunc               func(accountID, userID string) ([]*server.SetupKey, error)
	SaveUserFunc                    func(accountID string, user *server.User) (*server.UserInfo, error)
	GetNameServerGroupFunc          func(accountID, nsGroupID string) (*nbdns.NameServerGroup, error)
	CreateNameServerGroupFunc       func(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool) (*nbdns.NameServerGroup, error)
	SaveNameServerGroupFunc         func(accountID string, nsGroupToSave *nbdns.NameServerGroup) error
	UpdateNameServerGroupFunc       func(accountID, nsGroupID string, operations []server.NameServerGroupUpdateOperation) (*nbdns.NameServerGroup, error)
	DeleteNameServerGroupFunc       func(accountID, nsGroupID string) error
	ListNameServerGroupsFunc        func(accountID string) ([]*nbdns.NameServerGroup, error)
	CreateUserFunc                  func(accountID string, key *server.UserInfo) (*server.UserInfo, error)
	GetAccountFromTokenFunc         func(claims jwtclaims.AuthorizationClaims) (*server.Account, error)
}

// GetUsersFromAccount mock implementation of GetUsersFromAccount from server.AccountManager interface
func (am *MockAccountManager) GetUsersFromAccount(accountID string) ([]*server.UserInfo, error) {
	if am.GetUsersFromAccountFunc != nil {
		return am.GetUsersFromAccountFunc(accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetUsersFromAccount is not implemented")
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

// GetAccountByUser mock implementation of GetAccountByUser from server.AccountManager interface
func (am *MockAccountManager) GetAccountByUser(userId string) (*server.Account, error) {
	if am.GetAccountByUserFunc != nil {
		return am.GetAccountByUserFunc(userId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccountByUser is not implemented")
}

// CreateSetupKey mock implementation of CreateSetupKey from server.AccountManager interface
func (am *MockAccountManager) CreateSetupKey(
	accountId string,
	keyName string,
	keyType server.SetupKeyType,
	expiresIn time.Duration,
	autoGroups []string,
) (*server.SetupKey, error) {
	if am.CreateSetupKeyFunc != nil {
		return am.CreateSetupKeyFunc(accountId, keyName, keyType, expiresIn, autoGroups)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateSetupKey is not implemented")
}

// GetAccountById mock implementation of GetAccountById from server.AccountManager interface
func (am *MockAccountManager) GetAccountById(accountId string) (*server.Account, error) {
	if am.GetAccountByIdFunc != nil {
		return am.GetAccountByIdFunc(accountId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccountById is not implemented")
}

// GetAccountByUserOrAccountId mock implementation of GetAccountByUserOrAccountId from server.AccountManager interface
func (am *MockAccountManager) GetAccountByUserOrAccountId(
	userId, accountId, domain string,
) (*server.Account, error) {
	if am.GetAccountByUserOrAccountIdFunc != nil {
		return am.GetAccountByUserOrAccountIdFunc(userId, accountId, domain)
	}
	return nil, status.Errorf(
		codes.Unimplemented,
		"method GetAccountByUserOrAccountId is not implemented",
	)
}

// AccountExists mock implementation of AccountExists from server.AccountManager interface
func (am *MockAccountManager) AccountExists(accountId string) (*bool, error) {
	if am.AccountExistsFunc != nil {
		return am.AccountExistsFunc(accountId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method AccountExists is not implemented")
}

// GetPeer mock implementation of GetPeer from server.AccountManager interface
func (am *MockAccountManager) GetPeer(peerKey string) (*server.Peer, error) {
	if am.GetPeerFunc != nil {
		return am.GetPeerFunc(peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeer is not implemented")
}

// MarkPeerConnected mock implementation of MarkPeerConnected from server.AccountManager interface
func (am *MockAccountManager) MarkPeerConnected(peerKey string, connected bool) error {
	if am.MarkPeerConnectedFunc != nil {
		return am.MarkPeerConnectedFunc(peerKey, connected)
	}
	return status.Errorf(codes.Unimplemented, "method MarkPeerConnected is not implemented")
}

// RenamePeer mock implementation of RenamePeer from server.AccountManager interface
func (am *MockAccountManager) RenamePeer(
	accountId string,
	peerKey string,
	newName string,
) (*server.Peer, error) {
	if am.RenamePeerFunc != nil {
		return am.RenamePeerFunc(accountId, peerKey, newName)
	}
	return nil, status.Errorf(codes.Unimplemented, "method RenamePeer is not implemented")
}

// DeletePeer mock implementation of DeletePeer from server.AccountManager interface
func (am *MockAccountManager) DeletePeer(accountId string, peerKey string) (*server.Peer, error) {
	if am.DeletePeerFunc != nil {
		return am.DeletePeerFunc(accountId, peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method DeletePeer is not implemented")
}

// GetPeerByIP mock implementation of GetPeerByIP from server.AccountManager interface
func (am *MockAccountManager) GetPeerByIP(accountId string, peerIP string) (*server.Peer, error) {
	if am.GetPeerByIPFunc != nil {
		return am.GetPeerByIPFunc(accountId, peerIP)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeerByIP is not implemented")
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
) (*server.Peer, error) {
	if am.AddPeerFunc != nil {
		return am.AddPeerFunc(setupKey, userId, peer)
	}
	return nil, status.Errorf(codes.Unimplemented, "method AddPeer is not implemented")
}

// GetGroup mock implementation of GetGroup from server.AccountManager interface
func (am *MockAccountManager) GetGroup(accountID, groupID string) (*server.Group, error) {
	if am.GetGroupFunc != nil {
		return am.GetGroupFunc(accountID, groupID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetGroup is not implemented")
}

// SaveGroup mock implementation of SaveGroup from server.AccountManager interface
func (am *MockAccountManager) SaveGroup(accountID string, group *server.Group) error {
	if am.SaveGroupFunc != nil {
		return am.SaveGroupFunc(accountID, group)
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
func (am *MockAccountManager) GetRule(accountID, ruleID string) (*server.Rule, error) {
	if am.GetRuleFunc != nil {
		return am.GetRuleFunc(accountID, ruleID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetRule is not implemented")
}

// SaveRule mock implementation of SaveRule from server.AccountManager interface
func (am *MockAccountManager) SaveRule(accountID string, rule *server.Rule) error {
	if am.SaveRuleFunc != nil {
		return am.SaveRuleFunc(accountID, rule)
	}
	return status.Errorf(codes.Unimplemented, "method SaveRule is not implemented")
}

// UpdateRule mock implementation of UpdateRule from server.AccountManager interface
func (am *MockAccountManager) UpdateRule(accountID string, ruleID string, operations []server.RuleUpdateOperation) (*server.Rule, error) {
	if am.UpdateRuleFunc != nil {
		return am.UpdateRuleFunc(accountID, ruleID, operations)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdateRule not implemented")
}

// DeleteRule mock implementation of DeleteRule from server.AccountManager interface
func (am *MockAccountManager) DeleteRule(accountID, ruleID string) error {
	if am.DeleteRuleFunc != nil {
		return am.DeleteRuleFunc(accountID, ruleID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteRule is not implemented")
}

// ListRules mock implementation of ListRules from server.AccountManager interface
func (am *MockAccountManager) ListRules(accountID string) ([]*server.Rule, error) {
	if am.ListRulesFunc != nil {
		return am.ListRulesFunc(accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListRules is not implemented")
}

// UpdatePeerMeta mock implementation of UpdatePeerMeta from server.AccountManager interface
func (am *MockAccountManager) UpdatePeerMeta(peerKey string, meta server.PeerSystemMeta) error {
	if am.UpdatePeerMetaFunc != nil {
		return am.UpdatePeerMetaFunc(peerKey, meta)
	}
	return status.Errorf(codes.Unimplemented, "method UpdatePeerMetaFunc is not implemented")
}

// IsUserAdmin mock implementation of IsUserAdmin from server.AccountManager interface
func (am *MockAccountManager) IsUserAdmin(claims jwtclaims.AuthorizationClaims) (bool, error) {
	if am.IsUserAdminFunc != nil {
		return am.IsUserAdminFunc(claims)
	}
	return false, status.Errorf(codes.Unimplemented, "method IsUserAdmin is not implemented")
}

// UpdatePeerSSHKey mocks UpdatePeerSSHKey function of the account manager
func (am *MockAccountManager) UpdatePeerSSHKey(peerKey string, sshKey string) error {
	if am.UpdatePeerSSHKeyFunc != nil {
		return am.UpdatePeerSSHKeyFunc(peerKey, sshKey)
	}
	return status.Errorf(codes.Unimplemented, "method UpdatePeerSSHKey is is not implemented")
}

// UpdatePeer mocks UpdatePeerFunc function of the account manager
func (am *MockAccountManager) UpdatePeer(accountID string, peer *server.Peer) (*server.Peer, error) {
	if am.UpdatePeerFunc != nil {
		return am.UpdatePeerFunc(accountID, peer)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePeerFunc is is not implemented")
}

// CreateRoute mock implementation of CreateRoute from server.AccountManager interface
func (am *MockAccountManager) CreateRoute(accountID string, network, peer, description, netID string, masquerade bool, metric int, enabled bool) (*route.Route, error) {
	if am.GetRouteFunc != nil {
		return am.CreateRouteFunc(accountID, network, peer, description, netID, masquerade, metric, enabled)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateRoute is not implemented")
}

// GetRoute mock implementation of GetRoute from server.AccountManager interface
func (am *MockAccountManager) GetRoute(accountID, routeID string) (*route.Route, error) {
	if am.GetRouteFunc != nil {
		return am.GetRouteFunc(accountID, routeID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetRoute is not implemented")
}

// SaveRoute mock implementation of SaveRoute from server.AccountManager interface
func (am *MockAccountManager) SaveRoute(accountID string, route *route.Route) error {
	if am.SaveRouteFunc != nil {
		return am.SaveRouteFunc(accountID, route)
	}
	return status.Errorf(codes.Unimplemented, "method SaveRoute is not implemented")
}

// UpdateRoute mock implementation of UpdateRoute from server.AccountManager interface
func (am *MockAccountManager) UpdateRoute(accountID string, ruleID string, operations []server.RouteUpdateOperation) (*route.Route, error) {
	if am.UpdateRouteFunc != nil {
		return am.UpdateRouteFunc(accountID, ruleID, operations)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdateRoute not implemented")
}

// DeleteRoute mock implementation of DeleteRoute from server.AccountManager interface
func (am *MockAccountManager) DeleteRoute(accountID, routeID string) error {
	if am.DeleteRouteFunc != nil {
		return am.DeleteRouteFunc(accountID, routeID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteRoute is not implemented")
}

// ListRoutes mock implementation of ListRoutes from server.AccountManager interface
func (am *MockAccountManager) ListRoutes(accountID string) ([]*route.Route, error) {
	if am.ListRoutesFunc != nil {
		return am.ListRoutesFunc(accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListRoutes is not implemented")
}

// SaveSetupKey mocks SaveSetupKey of the AccountManager interface
func (am *MockAccountManager) SaveSetupKey(accountID string, key *server.SetupKey) (*server.SetupKey, error) {
	if am.SaveSetupKeyFunc != nil {
		return am.SaveSetupKeyFunc(accountID, key)
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
func (am *MockAccountManager) SaveUser(accountID string, user *server.User) (*server.UserInfo, error) {
	if am.SaveUserFunc != nil {
		return am.SaveUserFunc(accountID, user)
	}
	return nil, status.Errorf(codes.Unimplemented, "method SaveUser is not implemented")
}

// GetNameServerGroup mocks GetNameServerGroup of the AccountManager interface
func (am *MockAccountManager) GetNameServerGroup(accountID, nsGroupID string) (*nbdns.NameServerGroup, error) {
	if am.GetNameServerGroupFunc != nil {
		return am.GetNameServerGroupFunc(accountID, nsGroupID)
	}
	return nil, nil
}

// CreateNameServerGroup mocks CreateNameServerGroup of the AccountManager interface
func (am *MockAccountManager) CreateNameServerGroup(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool) (*nbdns.NameServerGroup, error) {
	if am.CreateNameServerGroupFunc != nil {
		return am.CreateNameServerGroupFunc(accountID, name, description, nameServerList, groups, primary, domains, enabled)
	}
	return nil, nil
}

// SaveNameServerGroup mocks SaveNameServerGroup of the AccountManager interface
func (am *MockAccountManager) SaveNameServerGroup(accountID string, nsGroupToSave *nbdns.NameServerGroup) error {
	if am.SaveNameServerGroupFunc != nil {
		return am.SaveNameServerGroupFunc(accountID, nsGroupToSave)
	}
	return nil
}

// UpdateNameServerGroup mocks UpdateNameServerGroup of the AccountManager interface
func (am *MockAccountManager) UpdateNameServerGroup(accountID, nsGroupID string, operations []server.NameServerGroupUpdateOperation) (*nbdns.NameServerGroup, error) {
	if am.UpdateNameServerGroupFunc != nil {
		return am.UpdateNameServerGroupFunc(accountID, nsGroupID, operations)
	}
	return nil, nil
}

// DeleteNameServerGroup mocks DeleteNameServerGroup of the AccountManager interface
func (am *MockAccountManager) DeleteNameServerGroup(accountID, nsGroupID string) error {
	if am.DeleteNameServerGroupFunc != nil {
		return am.DeleteNameServerGroupFunc(accountID, nsGroupID)
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
func (am *MockAccountManager) CreateUser(accountID string, invite *server.UserInfo) (*server.UserInfo, error) {
	if am.CreateUserFunc != nil {
		return am.CreateUserFunc(accountID, invite)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateUser is not implemented")
}

// GetAccountFromToken mocks GetAccountFromToken of the AccountManager interface
func (am *MockAccountManager) GetAccountFromToken(claims jwtclaims.AuthorizationClaims) (*server.Account, error) {
	if am.GetAccountFromTokenFunc != nil {
		return am.GetAccountFromTokenFunc(claims)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccountFromToken is not implemented")
}
