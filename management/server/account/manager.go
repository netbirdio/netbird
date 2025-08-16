package account

import (
	"context"
	"net"
	"net/netip"
	"time"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/idp"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type ExternalCacheManager nbcache.UserDataCache

type Manager interface {
	GetOrCreateAccountByUser(ctx context.Context, userId, domain string) (*types.Account, error)
	GetAccount(ctx context.Context, accountID string) (*types.Account, error)
	CreateSetupKey(ctx context.Context, accountID string, keyName string, keyType types.SetupKeyType, expiresIn time.Duration,
		autoGroups []string, usageLimit int, userID string, ephemeral bool, allowExtraDNSLabels bool) (*types.SetupKey, error)
	SaveSetupKey(ctx context.Context, accountID string, key *types.SetupKey, userID string) (*types.SetupKey, error)
	CreateUser(ctx context.Context, accountID, initiatorUserID string, key *types.UserInfo) (*types.UserInfo, error)
	DeleteUser(ctx context.Context, accountID, initiatorUserID string, targetUserID string) error
	DeleteRegularUsers(ctx context.Context, accountID, initiatorUserID string, targetUserIDs []string, userInfos map[string]*types.UserInfo) error
	InviteUser(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) error
	ListSetupKeys(ctx context.Context, accountID, userID string) ([]*types.SetupKey, error)
	SaveUser(ctx context.Context, accountID, initiatorUserID string, update *types.User) (*types.UserInfo, error)
	SaveOrAddUser(ctx context.Context, accountID, initiatorUserID string, update *types.User, addIfNotExists bool) (*types.UserInfo, error)
	SaveOrAddUsers(ctx context.Context, accountID, initiatorUserID string, updates []*types.User, addIfNotExists bool) ([]*types.UserInfo, error)
	GetSetupKey(ctx context.Context, accountID, userID, keyID string) (*types.SetupKey, error)
	GetAccountByID(ctx context.Context, accountID string, userID string) (*types.Account, error)
	GetAccountMeta(ctx context.Context, accountID string, userID string) (*types.AccountMeta, error)
	GetAccountOnboarding(ctx context.Context, accountID string, userID string) (*types.AccountOnboarding, error)
	AccountExists(ctx context.Context, accountID string) (bool, error)
	GetAccountIDByUserID(ctx context.Context, userID, domain string) (string, error)
	GetAccountIDFromUserAuth(ctx context.Context, userAuth nbcontext.UserAuth) (string, string, error)
	DeleteAccount(ctx context.Context, accountID, userID string) error
	GetUserByID(ctx context.Context, id string) (*types.User, error)
	GetUserFromUserAuth(ctx context.Context, userAuth nbcontext.UserAuth) (*types.User, error)
	ListUsers(ctx context.Context, accountID string) ([]*types.User, error)
	GetPeers(ctx context.Context, accountID, userID, nameFilter, ipFilter string) ([]*nbpeer.Peer, error)
	MarkPeerConnected(ctx context.Context, peerKey string, connected bool, realIP net.IP, accountID string) error
	DeletePeer(ctx context.Context, accountID, peerID, userID string) error
	UpdatePeer(ctx context.Context, accountID, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, error)
	UpdatePeerIP(ctx context.Context, accountID, userID, peerID string, newIP netip.Addr) error
	GetNetworkMap(ctx context.Context, peerID string) (*types.NetworkMap, error)
	GetPeerNetwork(ctx context.Context, peerID string) (*types.Network, error)
	AddPeer(ctx context.Context, setupKey, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error)
	CreatePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenName string, expiresIn int) (*types.PersonalAccessTokenGenerated, error)
	DeletePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) error
	GetPAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) (*types.PersonalAccessToken, error)
	GetAllPATs(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) ([]*types.PersonalAccessToken, error)
	GetUsersFromAccount(ctx context.Context, accountID, userID string) (map[string]*types.UserInfo, error)
	GetGroup(ctx context.Context, accountId, groupID, userID string) (*types.Group, error)
	GetAllGroups(ctx context.Context, accountID, userID string) ([]*types.Group, error)
	GetGroupByName(ctx context.Context, groupName, accountID string) (*types.Group, error)
	CreateGroup(ctx context.Context, accountID, userID string, group *types.Group) error
	UpdateGroup(ctx context.Context, accountID, userID string, group *types.Group) error
	CreateGroups(ctx context.Context, accountID, userID string, newGroups []*types.Group) error
	UpdateGroups(ctx context.Context, accountID, userID string, newGroups []*types.Group) error
	DeleteGroup(ctx context.Context, accountId, userId, groupID string) error
	DeleteGroups(ctx context.Context, accountId, userId string, groupIDs []string) error
	GroupAddPeer(ctx context.Context, accountId, groupID, peerID string) error
	GroupDeletePeer(ctx context.Context, accountId, groupID, peerID string) error
	GetPeerGroups(ctx context.Context, accountID, peerID string) ([]*types.Group, error)
	GetPolicy(ctx context.Context, accountID, policyID, userID string) (*types.Policy, error)
	SavePolicy(ctx context.Context, accountID, userID string, policy *types.Policy, create bool) (*types.Policy, error)
	DeletePolicy(ctx context.Context, accountID, policyID, userID string) error
	ListPolicies(ctx context.Context, accountID, userID string) ([]*types.Policy, error)
	GetRoute(ctx context.Context, accountID string, routeID route.ID, userID string) (*route.Route, error)
	CreateRoute(ctx context.Context, accountID string, prefix netip.Prefix, networkType route.NetworkType, domains domain.List, peerID string, peerGroupIDs []string, description string, netID route.NetID, masquerade bool, metric int, groups, accessControlGroupIDs []string, enabled bool, userID string, keepRoute bool) (*route.Route, error)
	SaveRoute(ctx context.Context, accountID, userID string, route *route.Route) error
	DeleteRoute(ctx context.Context, accountID string, routeID route.ID, userID string) error
	ListRoutes(ctx context.Context, accountID, userID string) ([]*route.Route, error)
	GetNameServerGroup(ctx context.Context, accountID, userID, nsGroupID string) (*nbdns.NameServerGroup, error)
	CreateNameServerGroup(ctx context.Context, accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string, searchDomainsEnabled bool) (*nbdns.NameServerGroup, error)
	SaveNameServerGroup(ctx context.Context, accountID, userID string, nsGroupToSave *nbdns.NameServerGroup) error
	DeleteNameServerGroup(ctx context.Context, accountID, nsGroupID, userID string) error
	ListNameServerGroups(ctx context.Context, accountID string, userID string) ([]*nbdns.NameServerGroup, error)
	GetDNSDomain(settings *types.Settings) string
	StoreEvent(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any)
	GetEvents(ctx context.Context, accountID, userID string) ([]*activity.Event, error)
	GetDNSSettings(ctx context.Context, accountID string, userID string) (*types.DNSSettings, error)
	SaveDNSSettings(ctx context.Context, accountID string, userID string, dnsSettingsToSave *types.DNSSettings) error
	GetPeer(ctx context.Context, accountID, peerID, userID string) (*nbpeer.Peer, error)
	UpdateAccountSettings(ctx context.Context, accountID, userID string, newSettings *types.Settings) (*types.Settings, error)
	UpdateAccountOnboarding(ctx context.Context, accountID, userID string, newOnboarding *types.AccountOnboarding) (*types.AccountOnboarding, error)
	LoginPeer(ctx context.Context, login types.PeerLogin) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error)                // used by peer gRPC API
	SyncPeer(ctx context.Context, sync types.PeerSync, accountID string) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error) // used by peer gRPC API
	GetAllConnectedPeers() (map[string]struct{}, error)
	HasConnectedChannel(peerID string) bool
	GetExternalCacheManager() ExternalCacheManager
	GetPostureChecks(ctx context.Context, accountID, postureChecksID, userID string) (*posture.Checks, error)
	SavePostureChecks(ctx context.Context, accountID, userID string, postureChecks *posture.Checks, create bool) (*posture.Checks, error)
	DeletePostureChecks(ctx context.Context, accountID, postureChecksID, userID string) error
	ListPostureChecks(ctx context.Context, accountID, userID string) ([]*posture.Checks, error)
	GetIdpManager() idp.Manager
	UpdateIntegratedValidator(ctx context.Context, accountID, userID, validator string, groups []string) error
	GroupValidation(ctx context.Context, accountId string, groups []string) (bool, error)
	GetValidatedPeers(ctx context.Context, accountID string) (map[string]struct{}, error)
	SyncAndMarkPeer(ctx context.Context, accountID string, peerPubKey string, meta nbpeer.PeerSystemMeta, realIP net.IP) (*nbpeer.Peer, *types.NetworkMap, []*posture.Checks, error)
	OnPeerDisconnected(ctx context.Context, accountID string, peerPubKey string) error
	SyncPeerMeta(ctx context.Context, peerPubKey string, meta nbpeer.PeerSystemMeta) error
	FindExistingPostureCheck(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error)
	GetAccountIDForPeerKey(ctx context.Context, peerKey string) (string, error)
	GetAccountSettings(ctx context.Context, accountID string, userID string) (*types.Settings, error)
	DeleteSetupKey(ctx context.Context, accountID, userID, keyID string) error
	UpdateAccountPeers(ctx context.Context, accountID string)
	BufferUpdateAccountPeers(ctx context.Context, accountID string)
	BuildUserInfosForAccount(ctx context.Context, accountID, initiatorUserID string, accountUsers []*types.User) (map[string]*types.UserInfo, error)
	SyncUserJWTGroups(ctx context.Context, userAuth nbcontext.UserAuth) error
	GetStore() store.Store
	GetOrCreateAccountByPrivateDomain(ctx context.Context, initiatorId, domain string) (*types.Account, bool, error)
	UpdateToPrimaryAccount(ctx context.Context, accountId string) (*types.Account, error)
	GetOwnerInfo(ctx context.Context, accountId string) (*types.UserInfo, error)
	GetCurrentUserInfo(ctx context.Context, userAuth nbcontext.UserAuth) (*users.UserInfoWithPermissions, error)
	CreateJob(ctx context.Context, peerID string, job *proto.JobRequest) error 
}
