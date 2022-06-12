package mock_server

import (
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MockAccountManager struct {
	GetOrCreateAccountByUserFunc          func(userId, domain string) (*server.Account, error)
	GetAccountByUserFunc                  func(userId string) (*server.Account, error)
	AddSetupKeyFunc                       func(accountId string, keyName string, keyType server.SetupKeyType, expiresIn *util.Duration) (*server.SetupKey, error)
	RevokeSetupKeyFunc                    func(accountId string, keyId string) (*server.SetupKey, error)
	RenameSetupKeyFunc                    func(accountId string, keyId string, newName string) (*server.SetupKey, error)
	GetAccountByIdFunc                    func(accountId string) (*server.Account, error)
	GetAccountByUserOrAccountIdFunc       func(userId, accountId, domain string) (*server.Account, error)
	GetAccountWithAuthorizationClaimsFunc func(claims jwtclaims.AuthorizationClaims) (*server.Account, error)
	IsUserAdminFunc                       func(claims jwtclaims.AuthorizationClaims) (bool, error)
	AccountExistsFunc                     func(accountId string) (*bool, error)
	GetPeerFunc                           func(peerKey string) (*server.Peer, error)
	MarkPeerConnectedFunc                 func(peerKey string, connected bool) error
	RenamePeerFunc                        func(accountId string, peerKey string, newName string) (*server.Peer, error)
	DeletePeerFunc                        func(accountId string, peerKey string) (*server.Peer, error)
	GetPeerByIPFunc                       func(accountId string, peerIP string) (*server.Peer, error)
	GetNetworkMapFunc                     func(peerKey string) (*server.NetworkMap, error)
	AddPeerFunc                           func(setupKey string, userId string, peer *server.Peer) (*server.Peer, error)
	GetGroupFunc                          func(accountID, groupID string) (*server.Group, error)
	SaveGroupFunc                         func(accountID string, group *server.Group) error
	DeleteGroupFunc                       func(accountID, groupID string) error
	ListGroupsFunc                        func(accountID string) ([]*server.Group, error)
	GroupAddPeerFunc                      func(accountID, groupID, peerKey string) error
	GroupDeletePeerFunc                   func(accountID, groupID, peerKey string) error
	GroupListPeersFunc                    func(accountID, groupID string) ([]*server.Peer, error)
	GetRuleFunc                           func(accountID, ruleID string) (*server.Rule, error)
	SaveRuleFunc                          func(accountID string, rule *server.Rule) error
	DeleteRuleFunc                        func(accountID, ruleID string) error
	ListRulesFunc                         func(accountID string) ([]*server.Rule, error)
	GetUsersFromAccountFunc               func(accountID string) ([]*server.UserInfo, error)
	UpdatePeerMetaFunc                    func(peerKey string, meta server.PeerSystemMeta) error
	UpdatePeerSSHKeyFunc                  func(peerKey string, sshKey string) error
}

func (am *MockAccountManager) GetUsersFromAccount(accountID string) ([]*server.UserInfo, error) {
	if am.GetUsersFromAccountFunc != nil {
		return am.GetUsersFromAccountFunc(accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetUsersFromAccount is not implemented")
}

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

func (am *MockAccountManager) GetAccountByUser(userId string) (*server.Account, error) {
	if am.GetAccountByUserFunc != nil {
		return am.GetAccountByUserFunc(userId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccountByUser is not implemented")
}

func (am *MockAccountManager) AddSetupKey(
	accountId string,
	keyName string,
	keyType server.SetupKeyType,
	expiresIn *util.Duration,
) (*server.SetupKey, error) {
	if am.AddSetupKeyFunc != nil {
		return am.AddSetupKeyFunc(accountId, keyName, keyType, expiresIn)
	}
	return nil, status.Errorf(codes.Unimplemented, "method AddSetupKey is not implemented")
}

func (am *MockAccountManager) RevokeSetupKey(
	accountId string,
	keyId string,
) (*server.SetupKey, error) {
	if am.RevokeSetupKeyFunc != nil {
		return am.RevokeSetupKeyFunc(accountId, keyId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method RevokeSetupKey is not implemented")
}

func (am *MockAccountManager) RenameSetupKey(
	accountId string,
	keyId string,
	newName string,
) (*server.SetupKey, error) {
	if am.RenameSetupKeyFunc != nil {
		return am.RenameSetupKeyFunc(accountId, keyId, newName)
	}
	return nil, status.Errorf(codes.Unimplemented, "method RenameSetupKey is not implemented")
}

func (am *MockAccountManager) GetAccountById(accountId string) (*server.Account, error) {
	if am.GetAccountByIdFunc != nil {
		return am.GetAccountByIdFunc(accountId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccountById is not implemented")
}

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

func (am *MockAccountManager) GetAccountWithAuthorizationClaims(
	claims jwtclaims.AuthorizationClaims,
) (*server.Account, error) {
	if am.GetAccountWithAuthorizationClaimsFunc != nil {
		return am.GetAccountWithAuthorizationClaimsFunc(claims)
	}
	return nil, status.Errorf(
		codes.Unimplemented,
		"method GetAccountWithAuthorizationClaims is not implemented",
	)
}

func (am *MockAccountManager) AccountExists(accountId string) (*bool, error) {
	if am.AccountExistsFunc != nil {
		return am.AccountExistsFunc(accountId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method AccountExists is not implemented")
}

func (am *MockAccountManager) GetPeer(peerKey string) (*server.Peer, error) {
	if am.GetPeerFunc != nil {
		return am.GetPeerFunc(peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeer is not implemented")
}

func (am *MockAccountManager) MarkPeerConnected(peerKey string, connected bool) error {
	if am.MarkPeerConnectedFunc != nil {
		return am.MarkPeerConnectedFunc(peerKey, connected)
	}
	return status.Errorf(codes.Unimplemented, "method MarkPeerConnected is not implemented")
}

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

func (am *MockAccountManager) DeletePeer(accountId string, peerKey string) (*server.Peer, error) {
	if am.DeletePeerFunc != nil {
		return am.DeletePeerFunc(accountId, peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method DeletePeer is not implemented")
}

func (am *MockAccountManager) GetPeerByIP(accountId string, peerIP string) (*server.Peer, error) {
	if am.GetPeerByIPFunc != nil {
		return am.GetPeerByIPFunc(accountId, peerIP)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeerByIP is not implemented")
}

func (am *MockAccountManager) GetNetworkMap(peerKey string) (*server.NetworkMap, error) {
	if am.GetNetworkMapFunc != nil {
		return am.GetNetworkMapFunc(peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetNetworkMap is not implemented")
}

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

func (am *MockAccountManager) GetGroup(accountID, groupID string) (*server.Group, error) {
	if am.GetGroupFunc != nil {
		return am.GetGroupFunc(accountID, groupID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetGroup is not implemented")
}

func (am *MockAccountManager) SaveGroup(accountID string, group *server.Group) error {
	if am.SaveGroupFunc != nil {
		return am.SaveGroupFunc(accountID, group)
	}
	return status.Errorf(codes.Unimplemented, "method SaveGroup is not implemented")
}

func (am *MockAccountManager) DeleteGroup(accountID, groupID string) error {
	if am.DeleteGroupFunc != nil {
		return am.DeleteGroupFunc(accountID, groupID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteGroup is not implemented")
}

func (am *MockAccountManager) ListGroups(accountID string) ([]*server.Group, error) {
	if am.ListGroupsFunc != nil {
		return am.ListGroupsFunc(accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListGroups is not implemented")
}

func (am *MockAccountManager) GroupAddPeer(accountID, groupID, peerKey string) error {
	if am.GroupAddPeerFunc != nil {
		return am.GroupAddPeerFunc(accountID, groupID, peerKey)
	}
	return status.Errorf(codes.Unimplemented, "method GroupAddPeer is not implemented")
}

func (am *MockAccountManager) GroupDeletePeer(accountID, groupID, peerKey string) error {
	if am.GroupDeletePeerFunc != nil {
		return am.GroupDeletePeerFunc(accountID, groupID, peerKey)
	}
	return status.Errorf(codes.Unimplemented, "method GroupDeletePeer is not implemented")
}

func (am *MockAccountManager) GroupListPeers(accountID, groupID string) ([]*server.Peer, error) {
	if am.GroupListPeersFunc != nil {
		return am.GroupListPeersFunc(accountID, groupID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GroupListPeers is not implemented")
}

func (am *MockAccountManager) GetRule(accountID, ruleID string) (*server.Rule, error) {
	if am.GetRuleFunc != nil {
		return am.GetRuleFunc(accountID, ruleID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetRule is not implemented")
}

func (am *MockAccountManager) SaveRule(accountID string, rule *server.Rule) error {
	if am.SaveRuleFunc != nil {
		return am.SaveRuleFunc(accountID, rule)
	}
	return status.Errorf(codes.Unimplemented, "method SaveRule is not implemented")
}

func (am *MockAccountManager) DeleteRule(accountID, ruleID string) error {
	if am.DeleteRuleFunc != nil {
		return am.DeleteRuleFunc(accountID, ruleID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteRule is not implemented")
}

func (am *MockAccountManager) ListRules(accountID string) ([]*server.Rule, error) {
	if am.ListRulesFunc != nil {
		return am.ListRulesFunc(accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListRules is not implemented")
}

func (am *MockAccountManager) UpdatePeerMeta(peerKey string, meta server.PeerSystemMeta) error {
	if am.UpdatePeerMetaFunc != nil {
		return am.UpdatePeerMetaFunc(peerKey, meta)
	}
	return status.Errorf(codes.Unimplemented, "method UpdatePeerMetaFunc is not implemented")
}

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
