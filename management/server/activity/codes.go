package activity

// Activity that triggered an Event
type Activity int

// Code is an activity string representation
type Code struct {
	message string
	code    string
}

const (
	// PeerAddedByUser indicates that a user added a new peer to the system
	PeerAddedByUser Activity = iota
	// PeerAddedWithSetupKey indicates that a new peer joined the system using a setup key
	PeerAddedWithSetupKey
	// UserJoined indicates that a new user joined the account
	UserJoined
	// UserInvited indicates that a new user was invited to join the account
	UserInvited
	// AccountCreated indicates that a new account has been created
	AccountCreated
	// PeerRemovedByUser indicates that a user removed a peer from the system
	PeerRemovedByUser
	// RuleAdded indicates that a user added a new rule
	RuleAdded
	// RuleUpdated indicates that a user updated a rule
	RuleUpdated
	// RuleRemoved indicates that a user removed a rule
	RuleRemoved
	// PolicyAdded indicates that a user added a new policy
	PolicyAdded
	// PolicyUpdated indicates that a user updated a policy
	PolicyUpdated
	// PolicyRemoved indicates that a user removed a policy
	PolicyRemoved
	// SetupKeyCreated indicates that a user created a new setup key
	SetupKeyCreated
	// SetupKeyUpdated indicates that a user updated a setup key
	SetupKeyUpdated
	// SetupKeyRevoked indicates that a user revoked a setup key
	SetupKeyRevoked
	// SetupKeyOverused indicates that setup key usage exhausted
	SetupKeyOverused
	// GroupCreated indicates that a user created a group
	GroupCreated
	// GroupUpdated indicates that a user updated a group
	GroupUpdated
	// GroupAddedToPeer indicates that a user added group to a peer
	GroupAddedToPeer
	// GroupRemovedFromPeer indicates that a user removed peer group
	GroupRemovedFromPeer
	// GroupAddedToUser indicates that a user added group to a user
	GroupAddedToUser
	// GroupRemovedFromUser indicates that a user removed a group from a user
	GroupRemovedFromUser
	// UserRoleUpdated indicates that a user changed the role of a user
	UserRoleUpdated
	// GroupAddedToSetupKey indicates that a user added group to a setup key
	GroupAddedToSetupKey
	// GroupRemovedFromSetupKey indicates that a user removed a group from a setup key
	GroupRemovedFromSetupKey
	// GroupAddedToDisabledManagementGroups indicates that a user added a group to the DNS setting Disabled management groups
	GroupAddedToDisabledManagementGroups
	// GroupRemovedFromDisabledManagementGroups indicates that a user removed a group from the DNS setting Disabled management groups
	GroupRemovedFromDisabledManagementGroups
	// RouteCreated indicates that a user created a route
	RouteCreated
	// RouteRemoved indicates that a user deleted a route
	RouteRemoved
	// RouteUpdated indicates that a user updated a route
	RouteUpdated
	// PeerSSHEnabled indicates that a user enabled SSH server on a peer
	PeerSSHEnabled
	// PeerSSHDisabled indicates that a user disabled SSH server on a peer
	PeerSSHDisabled
	// PeerRenamed indicates that a user renamed a peer
	PeerRenamed
	// PeerLoginExpirationEnabled indicates that a user enabled login expiration of a peer
	PeerLoginExpirationEnabled
	// PeerLoginExpirationDisabled indicates that a user disabled login expiration of a peer
	PeerLoginExpirationDisabled
	// NameserverGroupCreated indicates that a user created a nameservers group
	NameserverGroupCreated
	// NameserverGroupDeleted indicates that a user deleted a nameservers group
	NameserverGroupDeleted
	// NameserverGroupUpdated indicates that a user updated a nameservers group
	NameserverGroupUpdated
	// AccountPeerLoginExpirationEnabled indicates that a user enabled peer login expiration for the account
	AccountPeerLoginExpirationEnabled
	// AccountPeerLoginExpirationDisabled indicates that a user disabled peer login expiration for the account
	AccountPeerLoginExpirationDisabled
	// AccountPeerLoginExpirationDurationUpdated indicates that a user updated peer login expiration duration for the account
	AccountPeerLoginExpirationDurationUpdated
	// PersonalAccessTokenCreated indicates that a user created a personal access token
	PersonalAccessTokenCreated
	// PersonalAccessTokenDeleted indicates that a user deleted a personal access token
	PersonalAccessTokenDeleted
	// ServiceUserCreated indicates that a user created a service user
	ServiceUserCreated
	// ServiceUserDeleted indicates that a user deleted a service user
	ServiceUserDeleted
	// UserBlocked indicates that a user blocked another user
	UserBlocked
	// UserUnblocked indicates that a user unblocked another user
	UserUnblocked
	// UserDeleted indicates that a user deleted another user
	UserDeleted
	// GroupDeleted indicates that a user deleted group
	GroupDeleted
	// UserLoggedInPeer indicates that user logged in their peer with an interactive SSO login
	UserLoggedInPeer
	// PeerLoginExpired indicates that the user peer login has been expired and peer disconnected
	PeerLoginExpired
	// DashboardLogin indicates that the user logged in to the dashboard
	DashboardLogin
	// IntegrationCreated indicates that the user created an integration
	IntegrationCreated
	// IntegrationUpdated indicates that the user updated an integration
	IntegrationUpdated
	// IntegrationDeleted indicates that the user deleted an integration
	IntegrationDeleted
	// AccountPeerApprovalEnabled indicates that the user enabled peer approval for the account
	AccountPeerApprovalEnabled
	// AccountPeerApprovalDisabled indicates that the user disabled peer approval for the account
	AccountPeerApprovalDisabled
	// PeerApproved indicates that the peer has been approved
	PeerApproved
	// PeerApprovalRevoked indicates that the peer approval has been revoked
	PeerApprovalRevoked
	// TransferredOwnerRole indicates that the user transferred the owner role of the account
	TransferredOwnerRole
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
}

// StringCode returns a string code of the activity
func (a Activity) StringCode() string {
	if code, ok := activityMap[a]; ok {
		return code.code
	}
	return "UNKNOWN_ACTIVITY"
}

// Message returns a string representation of an activity
func (a Activity) Message() string {
	if code, ok := activityMap[a]; ok {
		return code.message
	}
	return "UNKNOWN_ACTIVITY"
}
