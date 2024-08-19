package mock_server

import (
	"context"
	"net"
	"net/netip"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/domain"
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
	GetOrCreateAccountByUserFunc func(ctx context.Context, userId, domain string) (*server.Account, error)
	CreateSetupKeyFunc           func(ctx context.Context, accountId string, keyName string, keyType server.SetupKeyType,
		expiresIn time.Duration, autoGroups []string, usageLimit int, userID string, ephemeral bool) (*server.SetupKey, error)
	GetSetupKeyFunc                     func(ctx context.Context, accountID, userID, keyID string) (*server.SetupKey, error)
	GetAccountByUserOrAccountIdFunc     func(ctx context.Context, userId, accountId, domain string) (*server.Account, error)
	GetUserFunc                         func(ctx context.Context, claims jwtclaims.AuthorizationClaims) (*server.User, error)
	ListUsersFunc                       func(ctx context.Context, accountID string) ([]*server.User, error)
	GetPeersFunc                        func(ctx context.Context, accountID, userID string) ([]*nbpeer.Peer, error)
	MarkPeerConnectedFunc               func(ctx context.Context, peerKey string, connected bool, realIP net.IP) error
	SyncAndMarkPeerFunc                 func(ctx context.Context, accountID string, peerPubKey string, meta nbpeer.PeerSystemMeta, realIP net.IP) (*nbpeer.Peer, *server.NetworkMap, []*posture.Checks, error)
	DeletePeerFunc                      func(ctx context.Context, accountID, peerKey, userID string) error
	GetNetworkMapFunc                   func(ctx context.Context, peerKey string) (*server.NetworkMap, error)
	GetPeerNetworkFunc                  func(ctx context.Context, peerKey string) (*server.Network, error)
	AddPeerFunc                         func(ctx context.Context, setupKey string, userId string, peer *nbpeer.Peer) (*nbpeer.Peer, *server.NetworkMap, []*posture.Checks, error)
	GetGroupFunc                        func(ctx context.Context, accountID, groupID, userID string) (*group.Group, error)
	GetAllGroupsFunc                    func(ctx context.Context, accountID, userID string) ([]*group.Group, error)
	GetGroupByNameFunc                  func(ctx context.Context, accountID, groupName string) (*group.Group, error)
	SaveGroupFunc                       func(ctx context.Context, accountID, userID string, group *group.Group) error
	SaveGroupsFunc                      func(ctx context.Context, accountID, userID string, groups []*group.Group) error
	DeleteGroupFunc                     func(ctx context.Context, accountID, userId, groupID string) error
	DeleteGroupsFunc                    func(ctx context.Context, accountId, userId string, groupIDs []string) error
	ListGroupsFunc                      func(ctx context.Context, accountID string) ([]*group.Group, error)
	GroupAddPeerFunc                    func(ctx context.Context, accountID, groupID, peerID string) error
	GroupDeletePeerFunc                 func(ctx context.Context, accountID, groupID, peerID string) error
	DeleteRuleFunc                      func(ctx context.Context, accountID, ruleID, userID string) error
	GetPolicyFunc                       func(ctx context.Context, accountID, policyID, userID string) (*server.Policy, error)
	SavePolicyFunc                      func(ctx context.Context, accountID, userID string, policy *server.Policy) error
	DeletePolicyFunc                    func(ctx context.Context, accountID, policyID, userID string) error
	ListPoliciesFunc                    func(ctx context.Context, accountID, userID string) ([]*server.Policy, error)
	GetUsersFromAccountFunc             func(ctx context.Context, accountID, userID string) ([]*server.UserInfo, error)
	GetAccountFromPATFunc               func(ctx context.Context, pat string) (*server.Account, *server.User, *server.PersonalAccessToken, error)
	MarkPATUsedFunc                     func(ctx context.Context, pat string) error
	UpdatePeerMetaFunc                  func(ctx context.Context, peerID string, meta nbpeer.PeerSystemMeta) error
	UpdatePeerSSHKeyFunc                func(ctx context.Context, peerID string, sshKey string) error
	UpdatePeerFunc                      func(ctx context.Context, accountID, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, error)
	CreateRouteFunc                     func(ctx context.Context, accountID string, prefix netip.Prefix, networkType route.NetworkType, domains domain.List, peer string, peerGroups []string, description string, netID route.NetID, masquerade bool, metric int, groups,accessControlGroupIDs []string, enabled bool, userID string, keepRoute bool) (*route.Route, error)
	GetRouteFunc                        func(ctx context.Context, accountID string, routeID route.ID, userID string) (*route.Route, error)
	SaveRouteFunc                       func(ctx context.Context, accountID string, userID string, route *route.Route) error
	DeleteRouteFunc                     func(ctx context.Context, accountID string, routeID route.ID, userID string) error
	ListRoutesFunc                      func(ctx context.Context, accountID, userID string) ([]*route.Route, error)
	SaveSetupKeyFunc                    func(ctx context.Context, accountID string, key *server.SetupKey, userID string) (*server.SetupKey, error)
	ListSetupKeysFunc                   func(ctx context.Context, accountID, userID string) ([]*server.SetupKey, error)
	SaveUserFunc                        func(ctx context.Context, accountID, userID string, user *server.User) (*server.UserInfo, error)
	SaveOrAddUserFunc                   func(ctx context.Context, accountID, userID string, user *server.User, addIfNotExists bool) (*server.UserInfo, error)
	SaveOrAddUsersFunc                  func(ctx context.Context, accountID, initiatorUserID string, update []*server.User, addIfNotExists bool) ([]*server.UserInfo, error)
	DeleteUserFunc                      func(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) error
	DeleteRegularUsersFunc              func(ctx context.Context, accountID, initiatorUserID string, targetUserIDs []string) error
	CreatePATFunc                       func(ctx context.Context, accountID string, initiatorUserID string, targetUserId string, tokenName string, expiresIn int) (*server.PersonalAccessTokenGenerated, error)
	DeletePATFunc                       func(ctx context.Context, accountID string, initiatorUserID string, targetUserId string, tokenID string) error
	GetPATFunc                          func(ctx context.Context, accountID string, initiatorUserID string, targetUserId string, tokenID string) (*server.PersonalAccessToken, error)
	GetAllPATsFunc                      func(ctx context.Context, accountID string, initiatorUserID string, targetUserId string) ([]*server.PersonalAccessToken, error)
	GetNameServerGroupFunc              func(ctx context.Context, accountID, userID, nsGroupID string) (*nbdns.NameServerGroup, error)
	CreateNameServerGroupFunc           func(ctx context.Context, accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string, searchDomainsEnabled bool) (*nbdns.NameServerGroup, error)
	SaveNameServerGroupFunc             func(ctx context.Context, accountID, userID string, nsGroupToSave *nbdns.NameServerGroup) error
	DeleteNameServerGroupFunc           func(ctx context.Context, accountID, nsGroupID, userID string) error
	ListNameServerGroupsFunc            func(ctx context.Context, accountID string, userID string) ([]*nbdns.NameServerGroup, error)
	CreateUserFunc                      func(ctx context.Context, accountID, userID string, key *server.UserInfo) (*server.UserInfo, error)
	GetAccountFromTokenFunc             func(ctx context.Context, claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error)
	CheckUserAccessByJWTGroupsFunc      func(ctx context.Context, claims jwtclaims.AuthorizationClaims) error
	DeleteAccountFunc                   func(ctx context.Context, accountID, userID string) error
	GetDNSDomainFunc                    func() string
	StoreEventFunc                      func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any)
	GetEventsFunc                       func(ctx context.Context, accountID, userID string) ([]*activity.Event, error)
	GetDNSSettingsFunc                  func(ctx context.Context, accountID, userID string) (*server.DNSSettings, error)
	SaveDNSSettingsFunc                 func(ctx context.Context, accountID, userID string, dnsSettingsToSave *server.DNSSettings) error
	GetPeerFunc                         func(ctx context.Context, accountID, peerID, userID string) (*nbpeer.Peer, error)
	UpdateAccountSettingsFunc           func(ctx context.Context, accountID, userID string, newSettings *server.Settings) (*server.Account, error)
	LoginPeerFunc                       func(ctx context.Context, login server.PeerLogin) (*nbpeer.Peer, *server.NetworkMap, []*posture.Checks, error)
	SyncPeerFunc                        func(ctx context.Context, sync server.PeerSync, account *server.Account) (*nbpeer.Peer, *server.NetworkMap, []*posture.Checks, error)
	InviteUserFunc                      func(ctx context.Context, accountID string, initiatorUserID string, targetUserEmail string) error
	GetAllConnectedPeersFunc            func() (map[string]struct{}, error)
	HasConnectedChannelFunc             func(peerID string) bool
	GetExternalCacheManagerFunc         func() server.ExternalCacheManager
	GetPostureChecksFunc                func(ctx context.Context, accountID, postureChecksID, userID string) (*posture.Checks, error)
	SavePostureChecksFunc               func(ctx context.Context, accountID, userID string, postureChecks *posture.Checks) error
	DeletePostureChecksFunc             func(ctx context.Context, accountID, postureChecksID, userID string) error
	ListPostureChecksFunc               func(ctx context.Context, accountID, userID string) ([]*posture.Checks, error)
	GetIdpManagerFunc                   func() idp.Manager
	UpdateIntegratedValidatorGroupsFunc func(ctx context.Context, accountID string, userID string, groups []string) error
	GroupValidationFunc                 func(ctx context.Context, accountId string, groups []string) (bool, error)
	SyncPeerMetaFunc                    func(ctx context.Context, peerPubKey string, meta nbpeer.PeerSystemMeta) error
	FindExistingPostureCheckFunc        func(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error)
	GetAccountIDForPeerKeyFunc          func(ctx context.Context, peerKey string) (string, error)
}

func (am *MockAccountManager) SyncAndMarkPeer(ctx context.Context, accountID string, peerPubKey string, meta nbpeer.PeerSystemMeta, realIP net.IP) (*nbpeer.Peer, *server.NetworkMap, []*posture.Checks, error) {
	if am.SyncAndMarkPeerFunc != nil {
		return am.SyncAndMarkPeerFunc(ctx, accountID, peerPubKey, meta, realIP)
	}
	return nil, nil, nil, status.Errorf(codes.Unimplemented, "method MarkPeerConnected is not implemented")
}

func (am *MockAccountManager) OnPeerDisconnected(_ context.Context, accountID string, peerPubKey string) error {
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
func (am *MockAccountManager) GetGroup(ctx context.Context, accountId, groupID, userID string) (*group.Group, error) {
	if am.GetGroupFunc != nil {
		return am.GetGroupFunc(ctx, accountId, groupID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetGroup is not implemented")
}

// GetAllGroups mock implementation of GetAllGroups from server.AccountManager interface
func (am *MockAccountManager) GetAllGroups(ctx context.Context, accountID, userID string) ([]*group.Group, error) {
	if am.GetAllGroupsFunc != nil {
		return am.GetAllGroupsFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAllGroups is not implemented")
}

// GetUsersFromAccount mock implementation of GetUsersFromAccount from server.AccountManager interface
func (am *MockAccountManager) GetUsersFromAccount(ctx context.Context, accountID string, userID string) ([]*server.UserInfo, error) {
	if am.GetUsersFromAccountFunc != nil {
		return am.GetUsersFromAccountFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetUsersFromAccount is not implemented")
}

// DeletePeer mock implementation of DeletePeer from server.AccountManager interface
func (am *MockAccountManager) DeletePeer(ctx context.Context, accountID, peerID, userID string) error {
	if am.DeletePeerFunc != nil {
		return am.DeletePeerFunc(ctx, accountID, peerID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeletePeer is not implemented")
}

// GetOrCreateAccountByUser mock implementation of GetOrCreateAccountByUser from server.AccountManager interface
func (am *MockAccountManager) GetOrCreateAccountByUser(
	ctx context.Context, userId, domain string,
) (*server.Account, error) {
	if am.GetOrCreateAccountByUserFunc != nil {
		return am.GetOrCreateAccountByUserFunc(ctx, userId, domain)
	}
	return nil, status.Errorf(
		codes.Unimplemented,
		"method GetOrCreateAccountByUser is not implemented",
	)
}

// CreateSetupKey mock implementation of CreateSetupKey from server.AccountManager interface
func (am *MockAccountManager) CreateSetupKey(
	ctx context.Context,
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
		return am.CreateSetupKeyFunc(ctx, accountID, keyName, keyType, expiresIn, autoGroups, usageLimit, userID, ephemeral)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateSetupKey is not implemented")
}

// GetAccountByUserOrAccountID mock implementation of GetAccountByUserOrAccountID from server.AccountManager interface
func (am *MockAccountManager) GetAccountByUserOrAccountID(
	ctx context.Context, userId, accountId, domain string,
) (*server.Account, error) {
	if am.GetAccountByUserOrAccountIdFunc != nil {
		return am.GetAccountByUserOrAccountIdFunc(ctx, userId, accountId, domain)
	}
	return nil, status.Errorf(
		codes.Unimplemented,
		"method GetAccountByUserOrAccountID is not implemented",
	)
}

// MarkPeerConnected mock implementation of MarkPeerConnected from server.AccountManager interface
func (am *MockAccountManager) MarkPeerConnected(ctx context.Context, peerKey string, connected bool, realIP net.IP, account *server.Account) error {
	if am.MarkPeerConnectedFunc != nil {
		return am.MarkPeerConnectedFunc(ctx, peerKey, connected, realIP)
	}
	return status.Errorf(codes.Unimplemented, "method MarkPeerConnected is not implemented")
}

// GetAccountFromPAT mock implementation of GetAccountFromPAT from server.AccountManager interface
func (am *MockAccountManager) GetAccountFromPAT(ctx context.Context, pat string) (*server.Account, *server.User, *server.PersonalAccessToken, error) {
	if am.GetAccountFromPATFunc != nil {
		return am.GetAccountFromPATFunc(ctx, pat)
	}
	return nil, nil, nil, status.Errorf(codes.Unimplemented, "method GetAccountFromPAT is not implemented")
}

// DeleteAccount mock implementation of DeleteAccount from server.AccountManager interface
func (am *MockAccountManager) DeleteAccount(ctx context.Context, accountID, userID string) error {
	if am.DeleteAccountFunc != nil {
		return am.DeleteAccountFunc(ctx, accountID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteAccount is not implemented")
}

// MarkPATUsed mock implementation of MarkPATUsed from server.AccountManager interface
func (am *MockAccountManager) MarkPATUsed(ctx context.Context, pat string) error {
	if am.MarkPATUsedFunc != nil {
		return am.MarkPATUsedFunc(ctx, pat)
	}
	return status.Errorf(codes.Unimplemented, "method MarkPATUsed is not implemented")
}

// CreatePAT mock implementation of GetPAT from server.AccountManager interface
func (am *MockAccountManager) CreatePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, name string, expiresIn int) (*server.PersonalAccessTokenGenerated, error) {
	if am.CreatePATFunc != nil {
		return am.CreatePATFunc(ctx, accountID, initiatorUserID, targetUserID, name, expiresIn)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreatePAT is not implemented")
}

// DeletePAT mock implementation of DeletePAT from server.AccountManager interface
func (am *MockAccountManager) DeletePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) error {
	if am.DeletePATFunc != nil {
		return am.DeletePATFunc(ctx, accountID, initiatorUserID, targetUserID, tokenID)
	}
	return status.Errorf(codes.Unimplemented, "method DeletePAT is not implemented")
}

// GetPAT mock implementation of GetPAT from server.AccountManager interface
func (am *MockAccountManager) GetPAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) (*server.PersonalAccessToken, error) {
	if am.GetPATFunc != nil {
		return am.GetPATFunc(ctx, accountID, initiatorUserID, targetUserID, tokenID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPAT is not implemented")
}

// GetAllPATs mock implementation of GetAllPATs from server.AccountManager interface
func (am *MockAccountManager) GetAllPATs(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) ([]*server.PersonalAccessToken, error) {
	if am.GetAllPATsFunc != nil {
		return am.GetAllPATsFunc(ctx, accountID, initiatorUserID, targetUserID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAllPATs is not implemented")
}

// GetNetworkMap mock implementation of GetNetworkMap from server.AccountManager interface
func (am *MockAccountManager) GetNetworkMap(ctx context.Context, peerKey string) (*server.NetworkMap, error) {
	if am.GetNetworkMapFunc != nil {
		return am.GetNetworkMapFunc(ctx, peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetNetworkMap is not implemented")
}

// GetPeerNetwork mock implementation of GetPeerNetwork from server.AccountManager interface
func (am *MockAccountManager) GetPeerNetwork(ctx context.Context, peerKey string) (*server.Network, error) {
	if am.GetPeerNetworkFunc != nil {
		return am.GetPeerNetworkFunc(ctx, peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeerNetwork is not implemented")
}

// AddPeer mock implementation of AddPeer from server.AccountManager interface
func (am *MockAccountManager) AddPeer(
	ctx context.Context,
	setupKey string,
	userId string,
	peer *nbpeer.Peer,
) (*nbpeer.Peer, *server.NetworkMap, []*posture.Checks, error) {
	if am.AddPeerFunc != nil {
		return am.AddPeerFunc(ctx, setupKey, userId, peer)
	}
	return nil, nil, nil, status.Errorf(codes.Unimplemented, "method AddPeer is not implemented")
}

// GetGroupByName mock implementation of GetGroupByName from server.AccountManager interface
func (am *MockAccountManager) GetGroupByName(ctx context.Context, accountID, groupName string) (*group.Group, error) {
	if am.GetGroupFunc != nil {
		return am.GetGroupByNameFunc(ctx, accountID, groupName)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetGroupByName is not implemented")
}

// SaveGroup mock implementation of SaveGroup from server.AccountManager interface
func (am *MockAccountManager) SaveGroup(ctx context.Context, accountID, userID string, group *group.Group) error {
	if am.SaveGroupFunc != nil {
		return am.SaveGroupFunc(ctx, accountID, userID, group)
	}
	return status.Errorf(codes.Unimplemented, "method SaveGroup is not implemented")
}

// SaveGroups mock implementation of SaveGroups from server.AccountManager interface
func (am *MockAccountManager) SaveGroups(ctx context.Context, accountID, userID string, groups []*group.Group) error {
	if am.SaveGroupsFunc != nil {
		return am.SaveGroupsFunc(ctx, accountID, userID, groups)
	}
	return status.Errorf(codes.Unimplemented, "method SaveGroups is not implemented")
}

// DeleteGroup mock implementation of DeleteGroup from server.AccountManager interface
func (am *MockAccountManager) DeleteGroup(ctx context.Context, accountId, userId, groupID string) error {
	if am.DeleteGroupFunc != nil {
		return am.DeleteGroupFunc(ctx, accountId, userId, groupID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteGroup is not implemented")
}

// DeleteGroups mock implementation of DeleteGroups from server.AccountManager interface
func (am *MockAccountManager) DeleteGroups(ctx context.Context, accountId, userId string, groupIDs []string) error {
	if am.DeleteGroupsFunc != nil {
		return am.DeleteGroupsFunc(ctx, accountId, userId, groupIDs)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteGroups is not implemented")
}

// ListGroups mock implementation of ListGroups from server.AccountManager interface
func (am *MockAccountManager) ListGroups(ctx context.Context, accountID string) ([]*group.Group, error) {
	if am.ListGroupsFunc != nil {
		return am.ListGroupsFunc(ctx, accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListGroups is not implemented")
}

// GroupAddPeer mock implementation of GroupAddPeer from server.AccountManager interface
func (am *MockAccountManager) GroupAddPeer(ctx context.Context, accountID, groupID, peerID string) error {
	if am.GroupAddPeerFunc != nil {
		return am.GroupAddPeerFunc(ctx, accountID, groupID, peerID)
	}
	return status.Errorf(codes.Unimplemented, "method GroupAddPeer is not implemented")
}

// GroupDeletePeer mock implementation of GroupDeletePeer from server.AccountManager interface
func (am *MockAccountManager) GroupDeletePeer(ctx context.Context, accountID, groupID, peerID string) error {
	if am.GroupDeletePeerFunc != nil {
		return am.GroupDeletePeerFunc(ctx, accountID, groupID, peerID)
	}
	return status.Errorf(codes.Unimplemented, "method GroupDeletePeer is not implemented")
}

// DeleteRule mock implementation of DeleteRule from server.AccountManager interface
func (am *MockAccountManager) DeleteRule(ctx context.Context, accountID, ruleID, userID string) error {
	if am.DeleteRuleFunc != nil {
		return am.DeleteRuleFunc(ctx, accountID, ruleID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeletePeerRule is not implemented")
}

// GetPolicy mock implementation of GetPolicy from server.AccountManager interface
func (am *MockAccountManager) GetPolicy(ctx context.Context, accountID, policyID, userID string) (*server.Policy, error) {
	if am.GetPolicyFunc != nil {
		return am.GetPolicyFunc(ctx, accountID, policyID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPolicy is not implemented")
}

// SavePolicy mock implementation of SavePolicy from server.AccountManager interface
func (am *MockAccountManager) SavePolicy(ctx context.Context, accountID, userID string, policy *server.Policy) error {
	if am.SavePolicyFunc != nil {
		return am.SavePolicyFunc(ctx, accountID, userID, policy)
	}
	return status.Errorf(codes.Unimplemented, "method SavePolicy is not implemented")
}

// DeletePolicy mock implementation of DeletePolicy from server.AccountManager interface
func (am *MockAccountManager) DeletePolicy(ctx context.Context, accountID, policyID, userID string) error {
	if am.DeletePolicyFunc != nil {
		return am.DeletePolicyFunc(ctx, accountID, policyID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeletePolicy is not implemented")
}

// ListPolicies mock implementation of ListPolicies from server.AccountManager interface
func (am *MockAccountManager) ListPolicies(ctx context.Context, accountID, userID string) ([]*server.Policy, error) {
	if am.ListPoliciesFunc != nil {
		return am.ListPoliciesFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListPolicies is not implemented")
}

// UpdatePeerMeta mock implementation of UpdatePeerMeta from server.AccountManager interface
func (am *MockAccountManager) UpdatePeerMeta(ctx context.Context, peerID string, meta nbpeer.PeerSystemMeta) error {
	if am.UpdatePeerMetaFunc != nil {
		return am.UpdatePeerMetaFunc(ctx, peerID, meta)
	}
	return status.Errorf(codes.Unimplemented, "method UpdatePeerMeta is not implemented")
}

// GetUser mock implementation of GetUser from server.AccountManager interface
func (am *MockAccountManager) GetUser(ctx context.Context, claims jwtclaims.AuthorizationClaims) (*server.User, error) {
	if am.GetUserFunc != nil {
		return am.GetUserFunc(ctx, claims)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetUser is not implemented")
}

func (am *MockAccountManager) ListUsers(ctx context.Context, accountID string) ([]*server.User, error) {
	if am.ListUsersFunc != nil {
		return am.ListUsersFunc(ctx, accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListUsers is not implemented")
}

// UpdatePeerSSHKey mocks UpdatePeerSSHKey function of the account manager
func (am *MockAccountManager) UpdatePeerSSHKey(ctx context.Context, peerID string, sshKey string) error {
	if am.UpdatePeerSSHKeyFunc != nil {
		return am.UpdatePeerSSHKeyFunc(ctx, peerID, sshKey)
	}
	return status.Errorf(codes.Unimplemented, "method UpdatePeerSSHKey is not implemented")
}

// UpdatePeer mocks UpdatePeerFunc function of the account manager
func (am *MockAccountManager) UpdatePeer(ctx context.Context, accountID, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, error) {
	if am.UpdatePeerFunc != nil {
		return am.UpdatePeerFunc(ctx, accountID, userID, peer)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePeer is not implemented")
}

// CreateRoute mock implementation of CreateRoute from server.AccountManager interface
func (am *MockAccountManager) CreateRoute(ctx context.Context, accountID string, prefix netip.Prefix, networkType route.NetworkType, domains domain.List, peerID string, peerGroupIDs []string, description string, netID route.NetID, masquerade bool, metric int, groups, accessControlGroupID []string, enabled bool, userID string, keepRoute bool) (*route.Route, error) {
	if am.CreateRouteFunc != nil {
		return am.CreateRouteFunc(ctx, accountID, prefix, networkType, domains, peerID, peerGroupIDs, description, netID, masquerade, metric, groups,accessControlGroupID, enabled, userID, keepRoute)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateRoute is not implemented")
}

// GetRoute mock implementation of GetRoute from server.AccountManager interface
func (am *MockAccountManager) GetRoute(ctx context.Context, accountID string, routeID route.ID, userID string) (*route.Route, error) {
	if am.GetRouteFunc != nil {
		return am.GetRouteFunc(ctx, accountID, routeID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetRoute is not implemented")
}

// SaveRoute mock implementation of SaveRoute from server.AccountManager interface
func (am *MockAccountManager) SaveRoute(ctx context.Context, accountID string, userID string, route *route.Route) error {
	if am.SaveRouteFunc != nil {
		return am.SaveRouteFunc(ctx, accountID, userID, route)
	}
	return status.Errorf(codes.Unimplemented, "method SaveRoute is not implemented")
}

// DeleteRoute mock implementation of DeleteRoute from server.AccountManager interface
func (am *MockAccountManager) DeleteRoute(ctx context.Context, accountID string, routeID route.ID, userID string) error {
	if am.DeleteRouteFunc != nil {
		return am.DeleteRouteFunc(ctx, accountID, routeID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteRoute is not implemented")
}

// ListRoutes mock implementation of ListRoutes from server.AccountManager interface
func (am *MockAccountManager) ListRoutes(ctx context.Context, accountID, userID string) ([]*route.Route, error) {
	if am.ListRoutesFunc != nil {
		return am.ListRoutesFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListRoutes is not implemented")
}

// SaveSetupKey mocks SaveSetupKey of the AccountManager interface
func (am *MockAccountManager) SaveSetupKey(ctx context.Context, accountID string, key *server.SetupKey, userID string) (*server.SetupKey, error) {
	if am.SaveSetupKeyFunc != nil {
		return am.SaveSetupKeyFunc(ctx, accountID, key, userID)
	}

	return nil, status.Errorf(codes.Unimplemented, "method SaveSetupKey is not implemented")
}

// GetSetupKey mocks GetSetupKey of the AccountManager interface
func (am *MockAccountManager) GetSetupKey(ctx context.Context, accountID, userID, keyID string) (*server.SetupKey, error) {
	if am.GetSetupKeyFunc != nil {
		return am.GetSetupKeyFunc(ctx, accountID, userID, keyID)
	}

	return nil, status.Errorf(codes.Unimplemented, "method GetSetupKey is not implemented")
}

// ListSetupKeys mocks ListSetupKeys of the AccountManager interface
func (am *MockAccountManager) ListSetupKeys(ctx context.Context, accountID, userID string) ([]*server.SetupKey, error) {
	if am.ListSetupKeysFunc != nil {
		return am.ListSetupKeysFunc(ctx, accountID, userID)
	}

	return nil, status.Errorf(codes.Unimplemented, "method ListSetupKeys is not implemented")
}

// SaveUser mocks SaveUser of the AccountManager interface
func (am *MockAccountManager) SaveUser(ctx context.Context, accountID, userID string, user *server.User) (*server.UserInfo, error) {
	if am.SaveUserFunc != nil {
		return am.SaveUserFunc(ctx, accountID, userID, user)
	}
	return nil, status.Errorf(codes.Unimplemented, "method SaveUser is not implemented")
}

// SaveOrAddUser mocks SaveOrAddUser of the AccountManager interface
func (am *MockAccountManager) SaveOrAddUser(ctx context.Context, accountID, userID string, user *server.User, addIfNotExists bool) (*server.UserInfo, error) {
	if am.SaveOrAddUserFunc != nil {
		return am.SaveOrAddUserFunc(ctx, accountID, userID, user, addIfNotExists)
	}
	return nil, status.Errorf(codes.Unimplemented, "method SaveOrAddUser is not implemented")
}

// SaveOrAddUsers mocks SaveOrAddUsers of the AccountManager interface
func (am *MockAccountManager) SaveOrAddUsers(ctx context.Context, accountID, userID string, users []*server.User, addIfNotExists bool) ([]*server.UserInfo, error) {
	if am.SaveOrAddUsersFunc != nil {
		return am.SaveOrAddUsersFunc(ctx, accountID, userID, users, addIfNotExists)
	}
	return nil, status.Errorf(codes.Unimplemented, "method SaveOrAddUsers is not implemented")
}

// DeleteUser mocks DeleteUser of the AccountManager interface
func (am *MockAccountManager) DeleteUser(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) error {
	if am.DeleteUserFunc != nil {
		return am.DeleteUserFunc(ctx, accountID, initiatorUserID, targetUserID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteUser is not implemented")
}

// DeleteRegularUsers mocks DeleteRegularUsers of the AccountManager interface
func (am *MockAccountManager) DeleteRegularUsers(ctx context.Context, accountID string, initiatorUserID string, targetUserIDs []string) error {
	if am.DeleteRegularUsersFunc != nil {
		return am.DeleteRegularUsersFunc(ctx, accountID, initiatorUserID, targetUserIDs)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteRegularUsers is not implemented")
}

func (am *MockAccountManager) InviteUser(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) error {
	if am.InviteUserFunc != nil {
		return am.InviteUserFunc(ctx, accountID, initiatorUserID, targetUserID)
	}
	return status.Errorf(codes.Unimplemented, "method InviteUser is not implemented")
}

// GetNameServerGroup mocks GetNameServerGroup of the AccountManager interface
func (am *MockAccountManager) GetNameServerGroup(ctx context.Context, accountID, userID, nsGroupID string) (*nbdns.NameServerGroup, error) {
	if am.GetNameServerGroupFunc != nil {
		return am.GetNameServerGroupFunc(ctx, accountID, userID, nsGroupID)
	}
	return nil, nil
}

// CreateNameServerGroup mocks CreateNameServerGroup of the AccountManager interface
func (am *MockAccountManager) CreateNameServerGroup(ctx context.Context, accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string, searchDomainsEnabled bool) (*nbdns.NameServerGroup, error) {
	if am.CreateNameServerGroupFunc != nil {
		return am.CreateNameServerGroupFunc(ctx, accountID, name, description, nameServerList, groups, primary, domains, enabled, userID, searchDomainsEnabled)
	}
	return nil, nil
}

// SaveNameServerGroup mocks SaveNameServerGroup of the AccountManager interface
func (am *MockAccountManager) SaveNameServerGroup(ctx context.Context, accountID, userID string, nsGroupToSave *nbdns.NameServerGroup) error {
	if am.SaveNameServerGroupFunc != nil {
		return am.SaveNameServerGroupFunc(ctx, accountID, userID, nsGroupToSave)
	}
	return nil
}

// DeleteNameServerGroup mocks DeleteNameServerGroup of the AccountManager interface
func (am *MockAccountManager) DeleteNameServerGroup(ctx context.Context, accountID, nsGroupID, userID string) error {
	if am.DeleteNameServerGroupFunc != nil {
		return am.DeleteNameServerGroupFunc(ctx, accountID, nsGroupID, userID)
	}
	return nil
}

// ListNameServerGroups mocks ListNameServerGroups of the AccountManager interface
func (am *MockAccountManager) ListNameServerGroups(ctx context.Context, accountID string, userID string) ([]*nbdns.NameServerGroup, error) {
	if am.ListNameServerGroupsFunc != nil {
		return am.ListNameServerGroupsFunc(ctx, accountID, userID)
	}
	return nil, nil
}

// CreateUser mocks CreateUser of the AccountManager interface
func (am *MockAccountManager) CreateUser(ctx context.Context, accountID, userID string, invite *server.UserInfo) (*server.UserInfo, error) {
	if am.CreateUserFunc != nil {
		return am.CreateUserFunc(ctx, accountID, userID, invite)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateUser is not implemented")
}

// GetAccountFromToken mocks GetAccountFromToken of the AccountManager interface
func (am *MockAccountManager) GetAccountFromToken(ctx context.Context, claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User,
	error,
) {
	if am.GetAccountFromTokenFunc != nil {
		return am.GetAccountFromTokenFunc(ctx, claims)
	}
	return nil, nil, status.Errorf(codes.Unimplemented, "method GetAccountFromToken is not implemented")
}

func (am *MockAccountManager) CheckUserAccessByJWTGroups(ctx context.Context, claims jwtclaims.AuthorizationClaims) error {
	if am.CheckUserAccessByJWTGroupsFunc != nil {
		return am.CheckUserAccessByJWTGroupsFunc(ctx, claims)
	}
	return status.Errorf(codes.Unimplemented, "method CheckUserAccessByJWTGroups is not implemented")
}

// GetPeers mocks GetPeers of the AccountManager interface
func (am *MockAccountManager) GetPeers(ctx context.Context, accountID, userID string) ([]*nbpeer.Peer, error) {
	if am.GetPeersFunc != nil {
		return am.GetPeersFunc(ctx, accountID, userID)
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
func (am *MockAccountManager) GetEvents(ctx context.Context, accountID, userID string) ([]*activity.Event, error) {
	if am.GetEventsFunc != nil {
		return am.GetEventsFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetEvents is not implemented")
}

// GetDNSSettings mocks GetDNSSettings of the AccountManager interface
func (am *MockAccountManager) GetDNSSettings(ctx context.Context, accountID string, userID string) (*server.DNSSettings, error) {
	if am.GetDNSSettingsFunc != nil {
		return am.GetDNSSettingsFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetDNSSettings is not implemented")
}

// SaveDNSSettings mocks SaveDNSSettings of the AccountManager interface
func (am *MockAccountManager) SaveDNSSettings(ctx context.Context, accountID string, userID string, dnsSettingsToSave *server.DNSSettings) error {
	if am.SaveDNSSettingsFunc != nil {
		return am.SaveDNSSettingsFunc(ctx, accountID, userID, dnsSettingsToSave)
	}
	return status.Errorf(codes.Unimplemented, "method SaveDNSSettings is not implemented")
}

// GetPeer mocks GetPeer of the AccountManager interface
func (am *MockAccountManager) GetPeer(ctx context.Context, accountID, peerID, userID string) (*nbpeer.Peer, error) {
	if am.GetPeerFunc != nil {
		return am.GetPeerFunc(ctx, accountID, peerID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeer is not implemented")
}

// UpdateAccountSettings mocks UpdateAccountSettings of the AccountManager interface
func (am *MockAccountManager) UpdateAccountSettings(ctx context.Context, accountID, userID string, newSettings *server.Settings) (*server.Account, error) {
	if am.UpdateAccountSettingsFunc != nil {
		return am.UpdateAccountSettingsFunc(ctx, accountID, userID, newSettings)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAccountSettings is not implemented")
}

// LoginPeer mocks LoginPeer of the AccountManager interface
func (am *MockAccountManager) LoginPeer(ctx context.Context, login server.PeerLogin) (*nbpeer.Peer, *server.NetworkMap, []*posture.Checks, error) {
	if am.LoginPeerFunc != nil {
		return am.LoginPeerFunc(ctx, login)
	}
	return nil, nil, nil, status.Errorf(codes.Unimplemented, "method LoginPeer is not implemented")
}

// SyncPeer mocks SyncPeer of the AccountManager interface
func (am *MockAccountManager) SyncPeer(ctx context.Context, sync server.PeerSync, account *server.Account) (*nbpeer.Peer, *server.NetworkMap, []*posture.Checks, error) {
	if am.SyncPeerFunc != nil {
		return am.SyncPeerFunc(ctx, sync, account)
	}
	return nil, nil, nil, status.Errorf(codes.Unimplemented, "method SyncPeer is not implemented")
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
func (am *MockAccountManager) StoreEvent(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
	if am.StoreEventFunc != nil {
		am.StoreEventFunc(ctx, initiatorID, targetID, accountID, activityID, meta)
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
func (am *MockAccountManager) GetPostureChecks(ctx context.Context, accountID, postureChecksID, userID string) (*posture.Checks, error) {
	if am.GetPostureChecksFunc != nil {
		return am.GetPostureChecksFunc(ctx, accountID, postureChecksID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPostureChecks is not implemented")

}

// SavePostureChecks mocks SavePostureChecks of the AccountManager interface
func (am *MockAccountManager) SavePostureChecks(ctx context.Context, accountID, userID string, postureChecks *posture.Checks) error {
	if am.SavePostureChecksFunc != nil {
		return am.SavePostureChecksFunc(ctx, accountID, userID, postureChecks)
	}
	return status.Errorf(codes.Unimplemented, "method SavePostureChecks is not implemented")
}

// DeletePostureChecks mocks DeletePostureChecks of the AccountManager interface
func (am *MockAccountManager) DeletePostureChecks(ctx context.Context, accountID, postureChecksID, userID string) error {
	if am.DeletePostureChecksFunc != nil {
		return am.DeletePostureChecksFunc(ctx, accountID, postureChecksID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeletePostureChecks is not implemented")

}

// ListPostureChecks mocks ListPostureChecks of the AccountManager interface
func (am *MockAccountManager) ListPostureChecks(ctx context.Context, accountID, userID string) ([]*posture.Checks, error) {
	if am.ListPostureChecksFunc != nil {
		return am.ListPostureChecksFunc(ctx, accountID, userID)
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
func (am *MockAccountManager) UpdateIntegratedValidatorGroups(ctx context.Context, accountID string, userID string, groups []string) error {
	if am.UpdateIntegratedValidatorGroupsFunc != nil {
		return am.UpdateIntegratedValidatorGroupsFunc(ctx, accountID, userID, groups)
	}
	return status.Errorf(codes.Unimplemented, "method UpdateIntegratedValidatorGroups is not implemented")
}

// GroupValidation mocks GroupValidation of the AccountManager interface
func (am *MockAccountManager) GroupValidation(ctx context.Context, accountId string, groups []string) (bool, error) {
	if am.GroupValidationFunc != nil {
		return am.GroupValidationFunc(ctx, accountId, groups)
	}
	return false, status.Errorf(codes.Unimplemented, "method GroupValidation is not implemented")
}

// SyncPeerMeta mocks SyncPeerMeta of the AccountManager interface
func (am *MockAccountManager) SyncPeerMeta(ctx context.Context, peerPubKey string, meta nbpeer.PeerSystemMeta) error {
	if am.SyncPeerMetaFunc != nil {
		return am.SyncPeerMetaFunc(ctx, peerPubKey, meta)
	}
	return status.Errorf(codes.Unimplemented, "method SyncPeerMeta is not implemented")
}

// FindExistingPostureCheck mocks FindExistingPostureCheck of the AccountManager interface
func (am *MockAccountManager) FindExistingPostureCheck(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error) {
	if am.FindExistingPostureCheckFunc != nil {
		return am.FindExistingPostureCheckFunc(accountID, checks)
	}
	return nil, status.Errorf(codes.Unimplemented, "method FindExistingPostureCheck is not implemented")
}

// GetAccountIDForPeerKey mocks GetAccountIDForPeerKey of the AccountManager interface
func (am *MockAccountManager) GetAccountIDForPeerKey(ctx context.Context, peerKey string) (string, error) {
	if am.GetAccountIDForPeerKeyFunc != nil {
		return am.GetAccountIDForPeerKeyFunc(ctx, peerKey)
	}
	return "", status.Errorf(codes.Unimplemented, "method GetAccountIDForPeerKey is not implemented")
}
