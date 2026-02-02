package mock_server

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/netbirdio/netbird/shared/auth"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

var _ account.Manager = (*MockAccountManager)(nil)

type MockAccountManager struct {
	GetOrCreateAccountByUserFunc func(ctx context.Context, userAuth auth.UserAuth) (*types.Account, error)
	GetAccountFunc               func(ctx context.Context, accountID string) (*types.Account, error)
	CreateSetupKeyFunc           func(ctx context.Context, accountId string, keyName string, keyType types.SetupKeyType,
		expiresIn time.Duration, autoGroups []string, usageLimit int, userID string, ephemeral bool, allowExtraDNSLabels bool) (*types.SetupKey, error)
	GetSetupKeyFunc                       func(ctx context.Context, accountID, userID, keyID string) (*types.SetupKey, error)
	AccountExistsFunc                     func(ctx context.Context, accountID string) (bool, error)
	GetAccountIDByUserIdFunc              func(ctx context.Context, userAuth auth.UserAuth) (string, error)
	GetUserFromUserAuthFunc               func(ctx context.Context, userAuth auth.UserAuth) (*types.User, error)
	ListUsersFunc                         func(ctx context.Context, accountID string) ([]*types.User, error)
	GetPeersFunc                          func(ctx context.Context, accountID, userID, nameFilter, ipFilter string) ([]*nbpeer.Peer, error)
	MarkPeerConnectedFunc                 func(ctx context.Context, peerKey string, connected bool, realIP net.IP) error
	SyncAndMarkPeerFunc                   func(ctx context.Context, accountID string, peerPubKey string, meta nbpeer.PeerSystemMeta, realIP net.IP) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, int64, error)
	DeletePeerFunc                        func(ctx context.Context, accountID, peerKey, userID string) error
	GetNetworkMapFunc                     func(ctx context.Context, peerKey string) (*types.NetworkMap, error)
	GetPeerNetworkFunc                    func(ctx context.Context, peerKey string) (*types.Network, error)
	AddPeerFunc                           func(ctx context.Context, accountID string, setupKey string, userId string, peer *nbpeer.Peer, temporary bool) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error)
	GetGroupFunc                          func(ctx context.Context, accountID, groupID, userID string) (*types.Group, error)
	GetAllGroupsFunc                      func(ctx context.Context, accountID, userID string) ([]*types.Group, error)
	GetGroupByNameFunc                    func(ctx context.Context, accountID, groupName string) (*types.Group, error)
	SaveGroupFunc                         func(ctx context.Context, accountID, userID string, group *types.Group, create bool) error
	SaveGroupsFunc                        func(ctx context.Context, accountID, userID string, groups []*types.Group, create bool) error
	DeleteGroupFunc                       func(ctx context.Context, accountID, userId, groupID string) error
	DeleteGroupsFunc                      func(ctx context.Context, accountId, userId string, groupIDs []string) error
	GroupAddPeerFunc                      func(ctx context.Context, accountID, groupID, peerID string) error
	GroupDeletePeerFunc                   func(ctx context.Context, accountID, groupID, peerID string) error
	GetPeerGroupsFunc                     func(ctx context.Context, accountID, peerID string) ([]*types.Group, error)
	DeleteRuleFunc                        func(ctx context.Context, accountID, ruleID, userID string) error
	GetPolicyFunc                         func(ctx context.Context, accountID, policyID, userID string) (*types.Policy, error)
	SavePolicyFunc                        func(ctx context.Context, accountID, userID string, policy *types.Policy, create bool) (*types.Policy, error)
	DeletePolicyFunc                      func(ctx context.Context, accountID, policyID, userID string) error
	ListPoliciesFunc                      func(ctx context.Context, accountID, userID string) ([]*types.Policy, error)
	GetUsersFromAccountFunc               func(ctx context.Context, accountID, userID string) (map[string]*types.UserInfo, error)
	UpdatePeerMetaFunc                    func(ctx context.Context, peerID string, meta nbpeer.PeerSystemMeta) error
	UpdatePeerFunc                        func(ctx context.Context, accountID, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, error)
	UpdatePeerIPFunc                      func(ctx context.Context, accountID, userID, peerID string, newIP netip.Addr) error
	CreateRouteFunc                       func(ctx context.Context, accountID string, prefix netip.Prefix, networkType route.NetworkType, domains domain.List, peer string, peerGroups []string, description string, netID route.NetID, masquerade bool, metric int, groups, accessControlGroupIDs []string, enabled bool, userID string, keepRoute bool, isSelected bool) (*route.Route, error)
	GetRouteFunc                          func(ctx context.Context, accountID string, routeID route.ID, userID string) (*route.Route, error)
	SaveRouteFunc                         func(ctx context.Context, accountID string, userID string, route *route.Route) error
	DeleteRouteFunc                       func(ctx context.Context, accountID string, routeID route.ID, userID string) error
	ListRoutesFunc                        func(ctx context.Context, accountID, userID string) ([]*route.Route, error)
	SaveSetupKeyFunc                      func(ctx context.Context, accountID string, key *types.SetupKey, userID string) (*types.SetupKey, error)
	ListSetupKeysFunc                     func(ctx context.Context, accountID, userID string) ([]*types.SetupKey, error)
	SaveUserFunc                          func(ctx context.Context, accountID, userID string, user *types.User) (*types.UserInfo, error)
	SaveOrAddUserFunc                     func(ctx context.Context, accountID, userID string, user *types.User, addIfNotExists bool) (*types.UserInfo, error)
	SaveOrAddUsersFunc                    func(ctx context.Context, accountID, initiatorUserID string, update []*types.User, addIfNotExists bool) ([]*types.UserInfo, error)
	DeleteUserFunc                        func(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) error
	DeleteRegularUsersFunc                func(ctx context.Context, accountID, initiatorUserID string, targetUserIDs []string, userInfos map[string]*types.UserInfo) error
	UpdateUserPasswordFunc                func(ctx context.Context, accountID, currentUserID, targetUserID string, oldPassword, newPassword string) error
	CreatePATFunc                         func(ctx context.Context, accountID string, initiatorUserID string, targetUserId string, tokenName string, expiresIn int) (*types.PersonalAccessTokenGenerated, error)
	DeletePATFunc                         func(ctx context.Context, accountID string, initiatorUserID string, targetUserId string, tokenID string) error
	GetPATFunc                            func(ctx context.Context, accountID string, initiatorUserID string, targetUserId string, tokenID string) (*types.PersonalAccessToken, error)
	GetAllPATsFunc                        func(ctx context.Context, accountID string, initiatorUserID string, targetUserId string) ([]*types.PersonalAccessToken, error)
	GetNameServerGroupFunc                func(ctx context.Context, accountID, userID, nsGroupID string) (*nbdns.NameServerGroup, error)
	CreateNameServerGroupFunc             func(ctx context.Context, accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string, searchDomainsEnabled bool) (*nbdns.NameServerGroup, error)
	SaveNameServerGroupFunc               func(ctx context.Context, accountID, userID string, nsGroupToSave *nbdns.NameServerGroup) error
	DeleteNameServerGroupFunc             func(ctx context.Context, accountID, nsGroupID, userID string) error
	ListNameServerGroupsFunc              func(ctx context.Context, accountID string, userID string) ([]*nbdns.NameServerGroup, error)
	CreateUserFunc                        func(ctx context.Context, accountID, userID string, key *types.UserInfo) (*types.UserInfo, error)
	GetAccountIDFromUserAuthFunc          func(ctx context.Context, userAuth auth.UserAuth) (string, string, error)
	DeleteAccountFunc                     func(ctx context.Context, accountID, userID string) error
	GetDNSDomainFunc                      func(settings *types.Settings) string
	StoreEventFunc                        func(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any)
	GetEventsFunc                         func(ctx context.Context, accountID, userID string) ([]*activity.Event, error)
	GetDNSSettingsFunc                    func(ctx context.Context, accountID, userID string) (*types.DNSSettings, error)
	SaveDNSSettingsFunc                   func(ctx context.Context, accountID, userID string, dnsSettingsToSave *types.DNSSettings) error
	GetPeerFunc                           func(ctx context.Context, accountID, peerID, userID string) (*nbpeer.Peer, error)
	UpdateAccountSettingsFunc             func(ctx context.Context, accountID, userID string, newSettings *types.Settings) (*types.Settings, error)
	LoginPeerFunc                         func(ctx context.Context, login types.PeerLogin) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error)
	SyncPeerFunc                          func(ctx context.Context, sync types.PeerSync, accountID string) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, int64, error)
	InviteUserFunc                        func(ctx context.Context, accountID string, initiatorUserID string, targetUserEmail string) error
	ApproveUserFunc                       func(ctx context.Context, accountID, initiatorUserID, targetUserID string) (*types.UserInfo, error)
	RejectUserFunc                        func(ctx context.Context, accountID, initiatorUserID, targetUserID string) error
	GetAllConnectedPeersFunc              func() (map[string]struct{}, error)
	HasConnectedChannelFunc               func(peerID string) bool
	GetExternalCacheManagerFunc           func() account.ExternalCacheManager
	GetPostureChecksFunc                  func(ctx context.Context, accountID, postureChecksID, userID string) (*posture.Checks, error)
	SavePostureChecksFunc                 func(ctx context.Context, accountID, userID string, postureChecks *posture.Checks, create bool) (*posture.Checks, error)
	DeletePostureChecksFunc               func(ctx context.Context, accountID, postureChecksID, userID string) error
	ListPostureChecksFunc                 func(ctx context.Context, accountID, userID string) ([]*posture.Checks, error)
	GetIdpManagerFunc                     func() idp.Manager
	UpdateIntegratedValidatorFunc         func(ctx context.Context, accountID, userID, validator string, groups []string) error
	GroupValidationFunc                   func(ctx context.Context, accountId string, groups []string) (bool, error)
	SyncPeerMetaFunc                      func(ctx context.Context, peerPubKey string, meta nbpeer.PeerSystemMeta) error
	FindExistingPostureCheckFunc          func(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error)
	GetAccountIDForPeerKeyFunc            func(ctx context.Context, peerKey string) (string, error)
	GetAccountByIDFunc                    func(ctx context.Context, accountID string, userID string) (*types.Account, error)
	GetUserByIDFunc                       func(ctx context.Context, id string) (*types.User, error)
	GetAccountSettingsFunc                func(ctx context.Context, accountID string, userID string) (*types.Settings, error)
	DeleteSetupKeyFunc                    func(ctx context.Context, accountID, userID, keyID string) error
	BuildUserInfosForAccountFunc          func(ctx context.Context, accountID, initiatorUserID string, accountUsers []*types.User) (map[string]*types.UserInfo, error)
	GetStoreFunc                          func() store.Store
	UpdateToPrimaryAccountFunc            func(ctx context.Context, accountId string) error
	GetOwnerInfoFunc                      func(ctx context.Context, accountID string) (*types.UserInfo, error)
	GetCurrentUserInfoFunc                func(ctx context.Context, userAuth auth.UserAuth) (*users.UserInfoWithPermissions, error)
	GetAccountMetaFunc                    func(ctx context.Context, accountID, userID string) (*types.AccountMeta, error)
	GetAccountOnboardingFunc              func(ctx context.Context, accountID, userID string) (*types.AccountOnboarding, error)
	UpdateAccountOnboardingFunc           func(ctx context.Context, accountID, userID string, onboarding *types.AccountOnboarding) (*types.AccountOnboarding, error)
	GetOrCreateAccountByPrivateDomainFunc func(ctx context.Context, initiatorId, domain string) (*types.Account, bool, error)

	AllowSyncFunc                  func(string, uint64) bool
	UpdateAccountPeersFunc         func(ctx context.Context, accountID string)
	BufferUpdateAccountPeersFunc   func(ctx context.Context, accountID string)
	RecalculateNetworkMapCacheFunc func(ctx context.Context, accountId string) error

	GetIdentityProviderFunc    func(ctx context.Context, accountID, idpID, userID string) (*types.IdentityProvider, error)
	GetIdentityProvidersFunc   func(ctx context.Context, accountID, userID string) ([]*types.IdentityProvider, error)
	CreateIdentityProviderFunc func(ctx context.Context, accountID, userID string, idp *types.IdentityProvider) (*types.IdentityProvider, error)
	UpdateIdentityProviderFunc func(ctx context.Context, accountID, idpID, userID string, idp *types.IdentityProvider) (*types.IdentityProvider, error)
	DeleteIdentityProviderFunc func(ctx context.Context, accountID, idpID, userID string) error
	CreatePeerJobFunc          func(ctx context.Context, accountID, peerID, userID string, job *types.Job) error
	GetAllPeerJobsFunc         func(ctx context.Context, accountID, userID, peerID string) ([]*types.Job, error)
	GetPeerJobByIDFunc         func(ctx context.Context, accountID, userID, peerID, jobID string) (*types.Job, error)
	CreateUserInviteFunc       func(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo, expiresIn int) (*types.UserInvite, error)
	AcceptUserInviteFunc       func(ctx context.Context, token, password string) error
	RegenerateUserInviteFunc   func(ctx context.Context, accountID, initiatorUserID, inviteID string, expiresIn int) (*types.UserInvite, error)
	GetUserInviteInfoFunc      func(ctx context.Context, token string) (*types.UserInviteInfo, error)
	ListUserInvitesFunc        func(ctx context.Context, accountID, initiatorUserID string) ([]*types.UserInvite, error)
	DeleteUserInviteFunc       func(ctx context.Context, accountID, initiatorUserID, inviteID string) error
}

func (am *MockAccountManager) CreatePeerJob(ctx context.Context, accountID, peerID, userID string, job *types.Job) error {
	if am.CreatePeerJobFunc != nil {
		return am.CreatePeerJobFunc(ctx, accountID, peerID, userID, job)
	}
	return status.Errorf(codes.Unimplemented, "method CreatePeerJob is not implemented")
}

func (am *MockAccountManager) GetAllPeerJobs(ctx context.Context, accountID, userID, peerID string) ([]*types.Job, error) {
	if am.GetAllPeerJobsFunc != nil {
		return am.GetAllPeerJobsFunc(ctx, accountID, userID, peerID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAllPeerJobs is not implemented")
}
func (am *MockAccountManager) GetPeerJobByID(ctx context.Context, accountID, userID, peerID, jobID string) (*types.Job, error) {
	if am.GetPeerJobByIDFunc != nil {
		return am.GetPeerJobByIDFunc(ctx, accountID, userID, peerID, jobID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeerJobByID is not implemented")
}

func (am *MockAccountManager) CreateGroup(ctx context.Context, accountID, userID string, group *types.Group) error {
	if am.SaveGroupFunc != nil {
		return am.SaveGroupFunc(ctx, accountID, userID, group, true)
	}
	return status.Errorf(codes.Unimplemented, "method CreateGroup is not implemented")
}

func (am *MockAccountManager) UpdateGroup(ctx context.Context, accountID, userID string, group *types.Group) error {
	if am.SaveGroupFunc != nil {
		return am.SaveGroupFunc(ctx, accountID, userID, group, false)
	}
	return status.Errorf(codes.Unimplemented, "method UpdateGroup is not implemented")
}

func (am *MockAccountManager) CreateGroups(ctx context.Context, accountID, userID string, newGroups []*types.Group) error {
	if am.SaveGroupsFunc != nil {
		return am.SaveGroupsFunc(ctx, accountID, userID, newGroups, true)
	}
	return status.Errorf(codes.Unimplemented, "method CreateGroups is not implemented")
}

func (am *MockAccountManager) UpdateGroups(ctx context.Context, accountID, userID string, newGroups []*types.Group) error {
	if am.SaveGroupsFunc != nil {
		return am.SaveGroupsFunc(ctx, accountID, userID, newGroups, false)
	}
	return status.Errorf(codes.Unimplemented, "method UpdateGroups is not implemented")
}

func (am *MockAccountManager) UpdateAccountPeers(ctx context.Context, accountID string) {
	if am.UpdateAccountPeersFunc != nil {
		am.UpdateAccountPeersFunc(ctx, accountID)
	}
}

func (am *MockAccountManager) BufferUpdateAccountPeers(ctx context.Context, accountID string) {
	if am.BufferUpdateAccountPeersFunc != nil {
		am.BufferUpdateAccountPeersFunc(ctx, accountID)
	}
}

func (am *MockAccountManager) DeleteSetupKey(ctx context.Context, accountID, userID, keyID string) error {
	if am.DeleteSetupKeyFunc != nil {
		return am.DeleteSetupKeyFunc(ctx, accountID, userID, keyID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteSetupKey is not implemented")
}

func (am *MockAccountManager) SyncAndMarkPeer(ctx context.Context, accountID string, peerPubKey string, meta nbpeer.PeerSystemMeta, realIP net.IP) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, int64, error) {
	if am.SyncAndMarkPeerFunc != nil {
		return am.SyncAndMarkPeerFunc(ctx, accountID, peerPubKey, meta, realIP)
	}
	return nil, nil, nil, 0, status.Errorf(codes.Unimplemented, "method MarkPeerConnected is not implemented")
}

func (am *MockAccountManager) OnPeerDisconnected(_ context.Context, accountID string, peerPubKey string) error {
	// TODO implement me
	panic("implement me")
}

func (am *MockAccountManager) GetValidatedPeers(ctx context.Context, accountID string) (map[string]struct{}, map[string]string, error) {
	account, err := am.GetAccountFunc(ctx, accountID)
	if err != nil {
		return nil, nil, err
	}

	approvedPeers := make(map[string]struct{})
	for id := range account.Peers {
		approvedPeers[id] = struct{}{}
	}
	return approvedPeers, nil, nil
}

// GetGroup mock implementation of GetGroup from server.AccountManager interface
func (am *MockAccountManager) GetGroup(ctx context.Context, accountId, groupID, userID string) (*types.Group, error) {
	if am.GetGroupFunc != nil {
		return am.GetGroupFunc(ctx, accountId, groupID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetGroup is not implemented")
}

// GetAllGroups mock implementation of GetAllGroups from server.AccountManager interface
func (am *MockAccountManager) GetAllGroups(ctx context.Context, accountID, userID string) ([]*types.Group, error) {
	if am.GetAllGroupsFunc != nil {
		return am.GetAllGroupsFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAllGroups is not implemented")
}

// GetUsersFromAccount mock implementation of GetUsersFromAccount from server.AccountManager interface
func (am *MockAccountManager) GetUsersFromAccount(ctx context.Context, accountID string, userID string) (map[string]*types.UserInfo, error) {
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
	ctx context.Context, userAuth auth.UserAuth,
) (*types.Account, error) {
	if am.GetOrCreateAccountByUserFunc != nil {
		return am.GetOrCreateAccountByUserFunc(ctx, userAuth)
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
	keyType types.SetupKeyType,
	expiresIn time.Duration,
	autoGroups []string,
	usageLimit int,
	userID string,
	ephemeral bool,
	allowExtraDNSLabels bool,
) (*types.SetupKey, error) {
	if am.CreateSetupKeyFunc != nil {
		return am.CreateSetupKeyFunc(ctx, accountID, keyName, keyType, expiresIn, autoGroups, usageLimit, userID, ephemeral, allowExtraDNSLabels)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateSetupKey is not implemented")
}

// AccountExists mock implementation of AccountExists from server.AccountManager interface
func (am *MockAccountManager) AccountExists(ctx context.Context, accountID string) (bool, error) {
	if am.AccountExistsFunc != nil {
		return am.AccountExistsFunc(ctx, accountID)
	}
	return false, status.Errorf(codes.Unimplemented, "method AccountExists is not implemented")
}

// GetAccountIDByUserID mock implementation of GetAccountIDByUserID from server.AccountManager interface
func (am *MockAccountManager) GetAccountIDByUserID(ctx context.Context, userAuth auth.UserAuth) (string, error) {
	if am.GetAccountIDByUserIdFunc != nil {
		return am.GetAccountIDByUserIdFunc(ctx, userAuth)
	}
	return "", status.Errorf(
		codes.Unimplemented,
		"method GetAccountIDByUserID is not implemented",
	)
}

// MarkPeerConnected mock implementation of MarkPeerConnected from server.AccountManager interface
func (am *MockAccountManager) MarkPeerConnected(ctx context.Context, peerKey string, connected bool, realIP net.IP, accountID string) error {
	if am.MarkPeerConnectedFunc != nil {
		return am.MarkPeerConnectedFunc(ctx, peerKey, connected, realIP)
	}
	return status.Errorf(codes.Unimplemented, "method MarkPeerConnected is not implemented")
}

// DeleteAccount mock implementation of DeleteAccount from server.AccountManager interface
func (am *MockAccountManager) DeleteAccount(ctx context.Context, accountID, userID string) error {
	if am.DeleteAccountFunc != nil {
		return am.DeleteAccountFunc(ctx, accountID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteAccount is not implemented")
}

// CreatePAT mock implementation of GetPAT from server.AccountManager interface
func (am *MockAccountManager) CreatePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, name string, expiresIn int) (*types.PersonalAccessTokenGenerated, error) {
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
func (am *MockAccountManager) GetPAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) (*types.PersonalAccessToken, error) {
	if am.GetPATFunc != nil {
		return am.GetPATFunc(ctx, accountID, initiatorUserID, targetUserID, tokenID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPAT is not implemented")
}

// GetAllPATs mock implementation of GetAllPATs from server.AccountManager interface
func (am *MockAccountManager) GetAllPATs(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) ([]*types.PersonalAccessToken, error) {
	if am.GetAllPATsFunc != nil {
		return am.GetAllPATsFunc(ctx, accountID, initiatorUserID, targetUserID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAllPATs is not implemented")
}

// GetNetworkMap mock implementation of GetNetworkMap from server.AccountManager interface
func (am *MockAccountManager) GetNetworkMap(ctx context.Context, peerKey string) (*types.NetworkMap, error) {
	if am.GetNetworkMapFunc != nil {
		return am.GetNetworkMapFunc(ctx, peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetNetworkMap is not implemented")
}

// GetPeerNetwork mock implementation of GetPeerNetwork from server.AccountManager interface
func (am *MockAccountManager) GetPeerNetwork(ctx context.Context, peerKey string) (*types.Network, error) {
	if am.GetPeerNetworkFunc != nil {
		return am.GetPeerNetworkFunc(ctx, peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeerNetwork is not implemented")
}

// AddPeer mock implementation of AddPeer from server.AccountManager interface
func (am *MockAccountManager) AddPeer(
	ctx context.Context,
	accountID string,
	setupKey string,
	userId string,
	peer *nbpeer.Peer,
	temporary bool,
) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error) {
	if am.AddPeerFunc != nil {
		return am.AddPeerFunc(ctx, accountID, setupKey, userId, peer, temporary)
	}
	return nil, nil, nil, status.Errorf(codes.Unimplemented, "method AddPeer is not implemented")
}

// GetGroupByName mock implementation of GetGroupByName from server.AccountManager interface
func (am *MockAccountManager) GetGroupByName(ctx context.Context, accountID, groupName string) (*types.Group, error) {
	if am.GetGroupFunc != nil {
		return am.GetGroupByNameFunc(ctx, accountID, groupName)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetGroupByName is not implemented")
}

// SaveGroup mock implementation of SaveGroup from server.AccountManager interface
func (am *MockAccountManager) SaveGroup(ctx context.Context, accountID, userID string, group *types.Group, create bool) error {
	if am.SaveGroupFunc != nil {
		return am.SaveGroupFunc(ctx, accountID, userID, group, create)
	}
	return status.Errorf(codes.Unimplemented, "method SaveGroup is not implemented")
}

// SaveGroups mock implementation of SaveGroups from server.AccountManager interface
func (am *MockAccountManager) SaveGroups(ctx context.Context, accountID, userID string, groups []*types.Group, create bool) error {
	if am.SaveGroupsFunc != nil {
		return am.SaveGroupsFunc(ctx, accountID, userID, groups, create)
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
func (am *MockAccountManager) GetPolicy(ctx context.Context, accountID, policyID, userID string) (*types.Policy, error) {
	if am.GetPolicyFunc != nil {
		return am.GetPolicyFunc(ctx, accountID, policyID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPolicy is not implemented")
}

// SavePolicy mock implementation of SavePolicy from server.AccountManager interface
func (am *MockAccountManager) SavePolicy(ctx context.Context, accountID, userID string, policy *types.Policy, create bool) (*types.Policy, error) {
	if am.SavePolicyFunc != nil {
		return am.SavePolicyFunc(ctx, accountID, userID, policy, create)
	}
	return nil, status.Errorf(codes.Unimplemented, "method SavePolicy is not implemented")
}

// DeletePolicy mock implementation of DeletePolicy from server.AccountManager interface
func (am *MockAccountManager) DeletePolicy(ctx context.Context, accountID, policyID, userID string) error {
	if am.DeletePolicyFunc != nil {
		return am.DeletePolicyFunc(ctx, accountID, policyID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeletePolicy is not implemented")
}

// ListPolicies mock implementation of ListPolicies from server.AccountManager interface
func (am *MockAccountManager) ListPolicies(ctx context.Context, accountID, userID string) ([]*types.Policy, error) {
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
func (am *MockAccountManager) GetUserFromUserAuth(ctx context.Context, userAuth auth.UserAuth) (*types.User, error) {
	if am.GetUserFromUserAuthFunc != nil {
		return am.GetUserFromUserAuthFunc(ctx, userAuth)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetUserFromUserAuth is not implemented")
}

func (am *MockAccountManager) ListUsers(ctx context.Context, accountID string) ([]*types.User, error) {
	if am.ListUsersFunc != nil {
		return am.ListUsersFunc(ctx, accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListUsers is not implemented")
}

// UpdatePeer mocks UpdatePeerFunc function of the account manager
func (am *MockAccountManager) UpdatePeer(ctx context.Context, accountID, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, error) {
	if am.UpdatePeerFunc != nil {
		return am.UpdatePeerFunc(ctx, accountID, userID, peer)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePeer is not implemented")
}

func (am *MockAccountManager) UpdatePeerIP(ctx context.Context, accountID, userID, peerID string, newIP netip.Addr) error {
	if am.UpdatePeerIPFunc != nil {
		return am.UpdatePeerIPFunc(ctx, accountID, userID, peerID, newIP)
	}
	return status.Errorf(codes.Unimplemented, "method UpdatePeerIP is not implemented")
}

// CreateRoute mock implementation of CreateRoute from server.AccountManager interface
func (am *MockAccountManager) CreateRoute(ctx context.Context, accountID string, prefix netip.Prefix, networkType route.NetworkType, domains domain.List, peerID string, peerGroupIDs []string, description string, netID route.NetID, masquerade bool, metric int, groups, accessControlGroupID []string, enabled bool, userID string, keepRoute bool, isSelected bool) (*route.Route, error) {
	if am.CreateRouteFunc != nil {
		return am.CreateRouteFunc(ctx, accountID, prefix, networkType, domains, peerID, peerGroupIDs, description, netID, masquerade, metric, groups, accessControlGroupID, enabled, userID, keepRoute, isSelected)
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
func (am *MockAccountManager) SaveSetupKey(ctx context.Context, accountID string, key *types.SetupKey, userID string) (*types.SetupKey, error) {
	if am.SaveSetupKeyFunc != nil {
		return am.SaveSetupKeyFunc(ctx, accountID, key, userID)
	}

	return nil, status.Errorf(codes.Unimplemented, "method SaveSetupKey is not implemented")
}

// GetSetupKey mocks GetSetupKey of the AccountManager interface
func (am *MockAccountManager) GetSetupKey(ctx context.Context, accountID, userID, keyID string) (*types.SetupKey, error) {
	if am.GetSetupKeyFunc != nil {
		return am.GetSetupKeyFunc(ctx, accountID, userID, keyID)
	}

	return nil, status.Errorf(codes.Unimplemented, "method GetSetupKey is not implemented")
}

// ListSetupKeys mocks ListSetupKeys of the AccountManager interface
func (am *MockAccountManager) ListSetupKeys(ctx context.Context, accountID, userID string) ([]*types.SetupKey, error) {
	if am.ListSetupKeysFunc != nil {
		return am.ListSetupKeysFunc(ctx, accountID, userID)
	}

	return nil, status.Errorf(codes.Unimplemented, "method ListSetupKeys is not implemented")
}

// SaveUser mocks SaveUser of the AccountManager interface
func (am *MockAccountManager) SaveUser(ctx context.Context, accountID, userID string, user *types.User) (*types.UserInfo, error) {
	if am.SaveUserFunc != nil {
		return am.SaveUserFunc(ctx, accountID, userID, user)
	}
	return nil, status.Errorf(codes.Unimplemented, "method SaveUser is not implemented")
}

// SaveOrAddUser mocks SaveOrAddUser of the AccountManager interface
func (am *MockAccountManager) SaveOrAddUser(ctx context.Context, accountID, userID string, user *types.User, addIfNotExists bool) (*types.UserInfo, error) {
	if am.SaveOrAddUserFunc != nil {
		return am.SaveOrAddUserFunc(ctx, accountID, userID, user, addIfNotExists)
	}
	return nil, status.Errorf(codes.Unimplemented, "method SaveOrAddUser is not implemented")
}

// SaveOrAddUsers mocks SaveOrAddUsers of the AccountManager interface
func (am *MockAccountManager) SaveOrAddUsers(ctx context.Context, accountID, userID string, users []*types.User, addIfNotExists bool) ([]*types.UserInfo, error) {
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
func (am *MockAccountManager) DeleteRegularUsers(ctx context.Context, accountID, initiatorUserID string, targetUserIDs []string, userInfos map[string]*types.UserInfo) error {
	if am.DeleteRegularUsersFunc != nil {
		return am.DeleteRegularUsersFunc(ctx, accountID, initiatorUserID, targetUserIDs, userInfos)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteRegularUsers is not implemented")
}

// UpdateUserPassword mocks UpdateUserPassword of the AccountManager interface
func (am *MockAccountManager) UpdateUserPassword(ctx context.Context, accountID, currentUserID, targetUserID string, oldPassword, newPassword string) error {
	if am.UpdateUserPasswordFunc != nil {
		return am.UpdateUserPasswordFunc(ctx, accountID, currentUserID, targetUserID, oldPassword, newPassword)
	}
	return status.Errorf(codes.Unimplemented, "method UpdateUserPassword is not implemented")
}

func (am *MockAccountManager) InviteUser(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) error {
	if am.InviteUserFunc != nil {
		return am.InviteUserFunc(ctx, accountID, initiatorUserID, targetUserID)
	}
	return status.Errorf(codes.Unimplemented, "method InviteUser is not implemented")
}

func (am *MockAccountManager) ApproveUser(ctx context.Context, accountID, initiatorUserID, targetUserID string) (*types.UserInfo, error) {
	if am.ApproveUserFunc != nil {
		return am.ApproveUserFunc(ctx, accountID, initiatorUserID, targetUserID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ApproveUser is not implemented")
}

func (am *MockAccountManager) RejectUser(ctx context.Context, accountID, initiatorUserID, targetUserID string) error {
	if am.RejectUserFunc != nil {
		return am.RejectUserFunc(ctx, accountID, initiatorUserID, targetUserID)
	}
	return status.Errorf(codes.Unimplemented, "method RejectUser is not implemented")
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
func (am *MockAccountManager) CreateUser(ctx context.Context, accountID, userID string, invite *types.UserInfo) (*types.UserInfo, error) {
	if am.CreateUserFunc != nil {
		return am.CreateUserFunc(ctx, accountID, userID, invite)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateUser is not implemented")
}

func (am *MockAccountManager) CreateUserInvite(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo, expiresIn int) (*types.UserInvite, error) {
	if am.CreateUserInviteFunc != nil {
		return am.CreateUserInviteFunc(ctx, accountID, initiatorUserID, invite, expiresIn)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateUserInvite is not implemented")
}

func (am *MockAccountManager) AcceptUserInvite(ctx context.Context, token, password string) error {
	if am.AcceptUserInviteFunc != nil {
		return am.AcceptUserInviteFunc(ctx, token, password)
	}
	return status.Errorf(codes.Unimplemented, "method AcceptUserInvite is not implemented")
}

func (am *MockAccountManager) RegenerateUserInvite(ctx context.Context, accountID, initiatorUserID, inviteID string, expiresIn int) (*types.UserInvite, error) {
	if am.RegenerateUserInviteFunc != nil {
		return am.RegenerateUserInviteFunc(ctx, accountID, initiatorUserID, inviteID, expiresIn)
	}
	return nil, status.Errorf(codes.Unimplemented, "method RegenerateUserInvite is not implemented")
}

func (am *MockAccountManager) GetUserInviteInfo(ctx context.Context, token string) (*types.UserInviteInfo, error) {
	if am.GetUserInviteInfoFunc != nil {
		return am.GetUserInviteInfoFunc(ctx, token)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetUserInviteInfo is not implemented")
}

func (am *MockAccountManager) ListUserInvites(ctx context.Context, accountID, initiatorUserID string) ([]*types.UserInvite, error) {
	if am.ListUserInvitesFunc != nil {
		return am.ListUserInvitesFunc(ctx, accountID, initiatorUserID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ListUserInvites is not implemented")
}

func (am *MockAccountManager) DeleteUserInvite(ctx context.Context, accountID, initiatorUserID, inviteID string) error {
	if am.DeleteUserInviteFunc != nil {
		return am.DeleteUserInviteFunc(ctx, accountID, initiatorUserID, inviteID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteUserInvite is not implemented")
}

func (am *MockAccountManager) GetAccountIDFromUserAuth(ctx context.Context, userAuth auth.UserAuth) (string, string, error) {
	if am.GetAccountIDFromUserAuthFunc != nil {
		return am.GetAccountIDFromUserAuthFunc(ctx, userAuth)
	}
	return "", "", status.Errorf(codes.Unimplemented, "method GetAccountIDFromUserAuth is not implemented")
}

// GetPeers mocks GetPeers of the AccountManager interface
func (am *MockAccountManager) GetPeers(ctx context.Context, accountID, userID, nameFilter, ipFilter string) ([]*nbpeer.Peer, error) {
	if am.GetPeersFunc != nil {
		return am.GetPeersFunc(ctx, accountID, userID, nameFilter, ipFilter)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeers is not implemented")
}

// GetDNSDomain mocks GetDNSDomain of the AccountManager interface
func (am *MockAccountManager) GetDNSDomain(settings *types.Settings) string {
	if am.GetDNSDomainFunc != nil {
		return am.GetDNSDomainFunc(settings)
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
func (am *MockAccountManager) GetDNSSettings(ctx context.Context, accountID string, userID string) (*types.DNSSettings, error) {
	if am.GetDNSSettingsFunc != nil {
		return am.GetDNSSettingsFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetDNSSettings is not implemented")
}

// SaveDNSSettings mocks SaveDNSSettings of the AccountManager interface
func (am *MockAccountManager) SaveDNSSettings(ctx context.Context, accountID string, userID string, dnsSettingsToSave *types.DNSSettings) error {
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
func (am *MockAccountManager) UpdateAccountSettings(ctx context.Context, accountID, userID string, newSettings *types.Settings) (*types.Settings, error) {
	if am.UpdateAccountSettingsFunc != nil {
		return am.UpdateAccountSettingsFunc(ctx, accountID, userID, newSettings)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAccountSettings is not implemented")
}

// LoginPeer mocks LoginPeer of the AccountManager interface
func (am *MockAccountManager) LoginPeer(ctx context.Context, login types.PeerLogin) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error) {
	if am.LoginPeerFunc != nil {
		return am.LoginPeerFunc(ctx, login)
	}
	return nil, nil, nil, status.Errorf(codes.Unimplemented, "method LoginPeer is not implemented")
}

// SyncPeer mocks SyncPeer of the AccountManager interface
func (am *MockAccountManager) SyncPeer(ctx context.Context, sync types.PeerSync, accountID string) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, int64, error) {
	if am.SyncPeerFunc != nil {
		return am.SyncPeerFunc(ctx, sync, accountID)
	}
	return nil, nil, nil, 0, status.Errorf(codes.Unimplemented, "method SyncPeer is not implemented")
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
func (am *MockAccountManager) GetExternalCacheManager() account.ExternalCacheManager {
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
func (am *MockAccountManager) SavePostureChecks(ctx context.Context, accountID, userID string, postureChecks *posture.Checks, create bool) (*posture.Checks, error) {
	if am.SavePostureChecksFunc != nil {
		return am.SavePostureChecksFunc(ctx, accountID, userID, postureChecks, create)
	}
	return nil, status.Errorf(codes.Unimplemented, "method SavePostureChecks is not implemented")
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

// UpdateIntegratedValidator mocks UpdateIntegratedApprovalGroups of the AccountManager interface
func (am *MockAccountManager) UpdateIntegratedValidator(ctx context.Context, accountID, userID, validator string, groups []string) error {
	if am.UpdateIntegratedValidatorFunc != nil {
		return am.UpdateIntegratedValidatorFunc(ctx, accountID, userID, validator, groups)
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

// GetAccountByID mocks GetAccountByID of the AccountManager interface
func (am *MockAccountManager) GetAccountByID(ctx context.Context, accountID string, userID string) (*types.Account, error) {
	if am.GetAccountByIDFunc != nil {
		return am.GetAccountByIDFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccountByID is not implemented")
}

// GetAccountByID mocks GetAccountByID of the AccountManager interface
func (am *MockAccountManager) GetAccountMeta(ctx context.Context, accountID string, userID string) (*types.AccountMeta, error) {
	if am.GetAccountMetaFunc != nil {
		return am.GetAccountMetaFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccountMeta is not implemented")
}

// GetAccountOnboarding mocks GetAccountOnboarding of the AccountManager interface
func (am *MockAccountManager) GetAccountOnboarding(ctx context.Context, accountID string, userID string) (*types.AccountOnboarding, error) {
	if am.GetAccountOnboardingFunc != nil {
		return am.GetAccountOnboardingFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccountOnboarding is not implemented")
}

// UpdateAccountOnboarding mocks UpdateAccountOnboarding of the AccountManager interface
func (am *MockAccountManager) UpdateAccountOnboarding(ctx context.Context, accountID string, userID string, onboarding *types.AccountOnboarding) (*types.AccountOnboarding, error) {
	if am.UpdateAccountOnboardingFunc != nil {
		return am.UpdateAccountOnboardingFunc(ctx, accountID, userID, onboarding)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAccountOnboarding is not implemented")
}

// GetUserByID mocks GetUserByID of the AccountManager interface
func (am *MockAccountManager) GetUserByID(ctx context.Context, id string) (*types.User, error) {
	if am.GetUserByIDFunc != nil {
		return am.GetUserByIDFunc(ctx, id)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetUserByID is not implemented")
}

func (am *MockAccountManager) GetAccountSettings(ctx context.Context, accountID string, userID string) (*types.Settings, error) {
	if am.GetAccountSettingsFunc != nil {
		return am.GetAccountSettingsFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccountSettings is not implemented")
}

func (am *MockAccountManager) GetAccount(ctx context.Context, accountID string) (*types.Account, error) {
	if am.GetAccountFunc != nil {
		return am.GetAccountFunc(ctx, accountID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccount is not implemented")
}

// GetPeerGroups mocks GetPeerGroups of the AccountManager interface
func (am *MockAccountManager) GetPeerGroups(ctx context.Context, accountID, peerID string) ([]*types.Group, error) {
	if am.GetPeerGroupsFunc != nil {
		return am.GetPeerGroupsFunc(ctx, accountID, peerID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeerGroups is not implemented")
}

// BuildUserInfosForAccount mocks BuildUserInfosForAccount of the AccountManager interface
func (am *MockAccountManager) BuildUserInfosForAccount(ctx context.Context, accountID, initiatorUserID string, accountUsers []*types.User) (map[string]*types.UserInfo, error) {
	if am.BuildUserInfosForAccountFunc != nil {
		return am.BuildUserInfosForAccountFunc(ctx, accountID, initiatorUserID, accountUsers)
	}
	return nil, status.Errorf(codes.Unimplemented, "method BuildUserInfosForAccount is not implemented")
}

func (am *MockAccountManager) SyncUserJWTGroups(ctx context.Context, userAuth auth.UserAuth) error {
	return status.Errorf(codes.Unimplemented, "method SyncUserJWTGroups is not implemented")
}

func (am *MockAccountManager) GetStore() store.Store {
	if am.GetStoreFunc != nil {
		return am.GetStoreFunc()
	}
	return nil
}

func (am *MockAccountManager) GetOrCreateAccountByPrivateDomain(ctx context.Context, initiatorId, domain string) (*types.Account, bool, error) {
	if am.GetOrCreateAccountByPrivateDomainFunc != nil {
		return am.GetOrCreateAccountByPrivateDomainFunc(ctx, initiatorId, domain)
	}
	return nil, false, status.Errorf(codes.Unimplemented, "method GetOrCreateAccountByPrivateDomainFunc is not implemented")
}

func (am *MockAccountManager) UpdateToPrimaryAccount(ctx context.Context, accountId string) error {
	if am.UpdateToPrimaryAccountFunc != nil {
		return am.UpdateToPrimaryAccountFunc(ctx, accountId)
	}
	return status.Errorf(codes.Unimplemented, "method UpdateToPrimaryAccount is not implemented")
}

func (am *MockAccountManager) GetOwnerInfo(ctx context.Context, accountId string) (*types.UserInfo, error) {
	if am.GetOwnerInfoFunc != nil {
		return am.GetOwnerInfoFunc(ctx, accountId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetOwnerInfo is not implemented")
}

func (am *MockAccountManager) GetCurrentUserInfo(ctx context.Context, userAuth auth.UserAuth) (*users.UserInfoWithPermissions, error) {
	if am.GetCurrentUserInfoFunc != nil {
		return am.GetCurrentUserInfoFunc(ctx, userAuth)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetCurrentUserInfo is not implemented")
}

func (am *MockAccountManager) AllowSync(key string, hash uint64) bool {
	if am.AllowSyncFunc != nil {
		return am.AllowSyncFunc(key, hash)
	}
	return true
}

func (am *MockAccountManager) RecalculateNetworkMapCache(ctx context.Context, accountID string) error {
	if am.RecalculateNetworkMapCacheFunc != nil {
		return am.RecalculateNetworkMapCacheFunc(ctx, accountID)
	}
	return nil
}

func (am *MockAccountManager) GetUserIDByPeerKey(ctx context.Context, peerKey string) (string, error) {
	return "something", nil
}

// GetIdentityProvider mocks GetIdentityProvider of the AccountManager interface
func (am *MockAccountManager) GetIdentityProvider(ctx context.Context, accountID, idpID, userID string) (*types.IdentityProvider, error) {
	if am.GetIdentityProviderFunc != nil {
		return am.GetIdentityProviderFunc(ctx, accountID, idpID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetIdentityProvider is not implemented")
}

// GetIdentityProviders mocks GetIdentityProviders of the AccountManager interface
func (am *MockAccountManager) GetIdentityProviders(ctx context.Context, accountID, userID string) ([]*types.IdentityProvider, error) {
	if am.GetIdentityProvidersFunc != nil {
		return am.GetIdentityProvidersFunc(ctx, accountID, userID)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetIdentityProviders is not implemented")
}

// CreateIdentityProvider mocks CreateIdentityProvider of the AccountManager interface
func (am *MockAccountManager) CreateIdentityProvider(ctx context.Context, accountID, userID string, idp *types.IdentityProvider) (*types.IdentityProvider, error) {
	if am.CreateIdentityProviderFunc != nil {
		return am.CreateIdentityProviderFunc(ctx, accountID, userID, idp)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateIdentityProvider is not implemented")
}

// UpdateIdentityProvider mocks UpdateIdentityProvider of the AccountManager interface
func (am *MockAccountManager) UpdateIdentityProvider(ctx context.Context, accountID, idpID, userID string, idp *types.IdentityProvider) (*types.IdentityProvider, error) {
	if am.UpdateIdentityProviderFunc != nil {
		return am.UpdateIdentityProviderFunc(ctx, accountID, idpID, userID, idp)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdateIdentityProvider is not implemented")
}

// DeleteIdentityProvider mocks DeleteIdentityProvider of the AccountManager interface
func (am *MockAccountManager) DeleteIdentityProvider(ctx context.Context, accountID, idpID, userID string) error {
	if am.DeleteIdentityProviderFunc != nil {
		return am.DeleteIdentityProviderFunc(ctx, accountID, idpID, userID)
	}
	return status.Errorf(codes.Unimplemented, "method DeleteIdentityProvider is not implemented")
}
