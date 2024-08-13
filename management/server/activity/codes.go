package activity

import "maps"

// Activity that triggered an Event
type Activity int

// Code is an activity string representation
type Code struct {
	Message string
	Code    string
}

// Existing consts must not be changed, as this will break the compatibility with the existing data
const (
	// PeerAddedByUser indicates that a user added a new peer to the system
	PeerAddedByUser Activity = 0
	// PeerAddedWithSetupKey indicates that a new peer joined the system using a setup key
	PeerAddedWithSetupKey Activity = 1
	// UserJoined indicates that a new user joined the account
	UserJoined Activity = 2
	// UserInvited indicates that a new user was invited to join the account
	UserInvited Activity = 3
	// AccountCreated indicates that a new account has been created
	AccountCreated Activity = 4
	// PeerRemovedByUser indicates that a user removed a peer from the system
	PeerRemovedByUser Activity = 5
	// RuleAdded indicates that a user added a new rule
	RuleAdded Activity = 6
	// RuleUpdated indicates that a user updated a rule
	RuleUpdated Activity = 7
	// RuleRemoved indicates that a user removed a rule
	RuleRemoved Activity = 8
	// PolicyAdded indicates that a user added a new policy
	PolicyAdded Activity = 9
	// PolicyUpdated indicates that a user updated a policy
	PolicyUpdated Activity = 10
	// PolicyRemoved indicates that a user removed a policy
	PolicyRemoved Activity = 11
	// SetupKeyCreated indicates that a user created a new setup key
	SetupKeyCreated Activity = 12
	// SetupKeyUpdated indicates that a user updated a setup key
	SetupKeyUpdated Activity = 13
	// SetupKeyRevoked indicates that a user revoked a setup key
	SetupKeyRevoked Activity = 14
	// SetupKeyOverused indicates that setup key usage exhausted
	SetupKeyOverused Activity = 15
	// GroupCreated indicates that a user created a group
	GroupCreated Activity = 16
	// GroupUpdated indicates that a user updated a group
	GroupUpdated Activity = 17
	// GroupAddedToPeer indicates that a user added group to a peer
	GroupAddedToPeer Activity = 18
	// GroupRemovedFromPeer indicates that a user removed peer group
	GroupRemovedFromPeer Activity = 19
	// GroupAddedToUser indicates that a user added group to a user
	GroupAddedToUser Activity = 20
	// GroupRemovedFromUser indicates that a user removed a group from a user
	GroupRemovedFromUser Activity = 21
	// UserRoleUpdated indicates that a user changed the role of a user
	UserRoleUpdated Activity = 22
	// GroupAddedToSetupKey indicates that a user added group to a setup key
	GroupAddedToSetupKey Activity = 23
	// GroupRemovedFromSetupKey indicates that a user removed a group from a setup key
	GroupRemovedFromSetupKey Activity = 24
	// GroupAddedToDisabledManagementGroups indicates that a user added a group to the DNS setting Disabled management groups
	GroupAddedToDisabledManagementGroups Activity = 25
	// GroupRemovedFromDisabledManagementGroups indicates that a user removed a group from the DNS setting Disabled management groups
	GroupRemovedFromDisabledManagementGroups Activity = 26
	// RouteCreated indicates that a user created a route
	RouteCreated Activity = 27
	// RouteRemoved indicates that a user deleted a route
	RouteRemoved Activity = 28
	// RouteUpdated indicates that a user updated a route
	RouteUpdated Activity = 29
	// PeerSSHEnabled indicates that a user enabled SSH server on a peer
	PeerSSHEnabled Activity = 30
	// PeerSSHDisabled indicates that a user disabled SSH server on a peer
	PeerSSHDisabled Activity = 31
	// PeerRenamed indicates that a user renamed a peer
	PeerRenamed Activity = 32
	// PeerLoginExpirationEnabled indicates that a user enabled login expiration of a peer
	PeerLoginExpirationEnabled Activity = 33
	// PeerLoginExpirationDisabled indicates that a user disabled login expiration of a peer
	PeerLoginExpirationDisabled Activity = 34
	// NameserverGroupCreated indicates that a user created a nameservers group
	NameserverGroupCreated Activity = 35
	// NameserverGroupDeleted indicates that a user deleted a nameservers group
	NameserverGroupDeleted Activity = 36
	// NameserverGroupUpdated indicates that a user updated a nameservers group
	NameserverGroupUpdated Activity = 37
	// AccountPeerLoginExpirationEnabled indicates that a user enabled peer login expiration for the account
	AccountPeerLoginExpirationEnabled Activity = 38
	// AccountPeerLoginExpirationDisabled indicates that a user disabled peer login expiration for the account
	AccountPeerLoginExpirationDisabled Activity = 39
	// AccountPeerLoginExpirationDurationUpdated indicates that a user updated peer login expiration duration for the account
	AccountPeerLoginExpirationDurationUpdated Activity = 40
	// PersonalAccessTokenCreated indicates that a user created a personal access token
	PersonalAccessTokenCreated Activity = 41
	// PersonalAccessTokenDeleted indicates that a user deleted a personal access token
	PersonalAccessTokenDeleted Activity = 42
	// ServiceUserCreated indicates that a user created a service user
	ServiceUserCreated Activity = 43
	// ServiceUserDeleted indicates that a user deleted a service user
	ServiceUserDeleted Activity = 44
	// UserBlocked indicates that a user blocked another user
	UserBlocked Activity = 45
	// UserUnblocked indicates that a user unblocked another user
	UserUnblocked Activity = 46
	// UserDeleted indicates that a user deleted another user
	UserDeleted Activity = 47
	// GroupDeleted indicates that a user deleted group
	GroupDeleted Activity = 48
	// UserLoggedInPeer indicates that user logged in their peer with an interactive SSO login
	UserLoggedInPeer Activity = 49
	// PeerLoginExpired indicates that the user peer login has been expired and peer disconnected
	PeerLoginExpired Activity = 50
	// DashboardLogin indicates that the user logged in to the dashboard
	DashboardLogin Activity = 51
	// IntegrationCreated indicates that the user created an integration
	IntegrationCreated Activity = 52
	// IntegrationUpdated indicates that the user updated an integration
	IntegrationUpdated Activity = 53
	// IntegrationDeleted indicates that the user deleted an integration
	IntegrationDeleted Activity = 54
	// AccountPeerApprovalEnabled indicates that the user enabled peer approval for the account
	AccountPeerApprovalEnabled Activity = 55
	// AccountPeerApprovalDisabled indicates that the user disabled peer approval for the account
	AccountPeerApprovalDisabled Activity = 56
	// PeerApproved indicates that the peer has been approved
	PeerApproved Activity = 57
	// PeerApprovalRevoked indicates that the peer approval has been revoked
	PeerApprovalRevoked Activity = 58
	// TransferredOwnerRole indicates that the user transferred the owner role of the account
	TransferredOwnerRole Activity = 59
	// PostureCheckCreated indicates that the user created a posture check
	PostureCheckCreated Activity = 60
	// PostureCheckUpdated indicates that the user updated a posture check
	PostureCheckUpdated Activity = 61
	// PostureCheckDeleted indicates that the user deleted a posture check
	PostureCheckDeleted Activity = 62
	// PeerIPv6Enabled indicates that a user enabled IPv6 for a peer
	PeerIPv6Enabled Activity = 63
	// PeerIPv6Disabled indicates that a user disabled IPv6 for a peer
	PeerIPv6Disabled Activity = 64
	// PeerIPv6InheritEnabled indicates that IPv6 was enabled for a peer due to a change in group memberships.
	PeerIPv6InheritEnabled Activity = 65
	// PeerIPv6InheritDisabled indicates that IPv6 was disabled for a peer due to a change in group memberships.
	PeerIPv6InheritDisabled Activity = 66
)

var activityMap = map[Activity]Code{
	PeerAddedByUser:                          {"Peer added", "user.peer.add"},
	PeerAddedWithSetupKey:                    {"Peer added", "setupkey.peer.add"},
	UserJoined:                               {"User joined", "user.join"},
	UserInvited:                              {"User invited", "user.invite"},
	AccountCreated:                           {"Account created", "account.create"},
	PeerRemovedByUser:                        {"Peer deleted", "user.peer.delete"},
	RuleAdded:                                {"Rule added", "rule.add"},
	RuleUpdated:                              {"Rule updated", "rule.update"},
	RuleRemoved:                              {"Rule deleted", "rule.delete"},
	PolicyAdded:                              {"Policy added", "policy.add"},
	PolicyUpdated:                            {"Policy updated", "policy.update"},
	PolicyRemoved:                            {"Policy deleted", "policy.delete"},
	SetupKeyCreated:                          {"Setup key created", "setupkey.add"},
	SetupKeyUpdated:                          {"Setup key updated", "setupkey.update"},
	SetupKeyRevoked:                          {"Setup key revoked", "setupkey.revoke"},
	SetupKeyOverused:                         {"Setup key overused", "setupkey.overuse"},
	GroupCreated:                             {"Group created", "group.add"},
	GroupUpdated:                             {"Group updated", "group.update"},
	GroupAddedToPeer:                         {"Group added to peer", "peer.group.add"},
	GroupRemovedFromPeer:                     {"Group removed from peer", "peer.group.delete"},
	GroupAddedToUser:                         {"Group added to user", "user.group.add"},
	GroupRemovedFromUser:                     {"Group removed from user", "user.group.delete"},
	UserRoleUpdated:                          {"User role updated", "user.role.update"},
	GroupAddedToSetupKey:                     {"Group added to setup key", "setupkey.group.add"},
	GroupRemovedFromSetupKey:                 {"Group removed from user setup key", "setupkey.group.delete"},
	GroupAddedToDisabledManagementGroups:     {"Group added to disabled management DNS setting", "dns.setting.disabled.management.group.add"},
	GroupRemovedFromDisabledManagementGroups: {"Group removed from disabled management DNS setting", "dns.setting.disabled.management.group.delete"},
	RouteCreated:                             {"Route created", "route.add"},
	RouteRemoved:                             {"Route deleted", "route.delete"},
	RouteUpdated:                             {"Route updated", "route.update"},
	PeerSSHEnabled:                           {"Peer SSH server enabled", "peer.ssh.enable"},
	PeerSSHDisabled:                          {"Peer SSH server disabled", "peer.ssh.disable"},
	PeerRenamed:                              {"Peer renamed", "peer.rename"},
	PeerLoginExpirationEnabled:               {"Peer login expiration enabled", "peer.login.expiration.enable"},
	PeerLoginExpirationDisabled:              {"Peer login expiration disabled", "peer.login.expiration.disable"},
	NameserverGroupCreated:                   {"Nameserver group created", "nameserver.group.add"},
	NameserverGroupDeleted:                   {"Nameserver group deleted", "nameserver.group.delete"},
	NameserverGroupUpdated:                   {"Nameserver group updated", "nameserver.group.update"},
	AccountPeerLoginExpirationDurationUpdated: {"Account peer login expiration duration updated", "account.setting.peer.login.expiration.update"},
	AccountPeerLoginExpirationEnabled:         {"Account peer login expiration enabled", "account.setting.peer.login.expiration.enable"},
	AccountPeerLoginExpirationDisabled:        {"Account peer login expiration disabled", "account.setting.peer.login.expiration.disable"},
	PersonalAccessTokenCreated:                {"Personal access token created", "personal.access.token.create"},
	PersonalAccessTokenDeleted:                {"Personal access token deleted", "personal.access.token.delete"},
	ServiceUserCreated:                        {"Service user created", "service.user.create"},
	ServiceUserDeleted:                        {"Service user deleted", "service.user.delete"},
	UserBlocked:                               {"User blocked", "user.block"},
	UserUnblocked:                             {"User unblocked", "user.unblock"},
	UserDeleted:                               {"User deleted", "user.delete"},
	GroupDeleted:                              {"Group deleted", "group.delete"},
	UserLoggedInPeer:                          {"User logged in peer", "user.peer.login"},
	PeerLoginExpired:                          {"Peer login expired", "peer.login.expire"},
	DashboardLogin:                            {"Dashboard login", "dashboard.login"},
	IntegrationCreated:                        {"Integration created", "integration.create"},
	IntegrationUpdated:                        {"Integration updated", "integration.update"},
	IntegrationDeleted:                        {"Integration deleted", "integration.delete"},
	AccountPeerApprovalEnabled:                {"Account peer approval enabled", "account.setting.peer.approval.enable"},
	AccountPeerApprovalDisabled:               {"Account peer approval disabled", "account.setting.peer.approval.disable"},
	PeerApproved:                              {"Peer approved", "peer.approve"},
	PeerApprovalRevoked:                       {"Peer approval revoked", "peer.approval.revoke"},
	TransferredOwnerRole:                      {"Transferred owner role", "transferred.owner.role"},
	PostureCheckCreated:                       {"Posture check created", "posture.check.created"},
	PostureCheckUpdated:                       {"Posture check updated", "posture.check.updated"},
	PostureCheckDeleted:                       {"Posture check deleted", "posture.check.deleted"},
	PeerIPv6Enabled:                           {"Peer IPv6 enabled by user", "peer.ipv6.manual_enable"},
	PeerIPv6Disabled:                          {"Peer IPv6 disabled by user", "peer.ipv6.manual_disable"},
	PeerIPv6InheritDisabled:                   {"Peer IPv6 disabled due to change in group settings or membership", "peer.ipv6.inherit_disable"},
	PeerIPv6InheritEnabled:                    {"Peer IPv6 enabled due to change in group settings or membership", "peer.ipv6.inherit_enable"},
}

// StringCode returns a string code of the activity
func (a Activity) StringCode() string {
	if code, ok := activityMap[a]; ok {
		return code.Code
	}
	return "UNKNOWN_ACTIVITY"
}

// Message returns a string representation of an activity
func (a Activity) Message() string {
	if code, ok := activityMap[a]; ok {
		return code.Message
	}
	return "UNKNOWN_ACTIVITY"
}

// RegisterActivityMap adds new codes to the activity map
func RegisterActivityMap(codes map[Activity]Code) {
	maps.Copy(activityMap, codes)
}
