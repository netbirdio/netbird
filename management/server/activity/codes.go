package activity

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
)

const (
	// PeerAddedByUserMessage is a human-readable text message of the PeerAddedByUser activity
	PeerAddedByUserMessage string = "Peer added"
	// PeerAddedWithSetupKeyMessage is a human-readable text message of the PeerAddedWithSetupKey activity
	PeerAddedWithSetupKeyMessage = PeerAddedByUserMessage
	// UserJoinedMessage is a human-readable text message of the UserJoined activity
	UserJoinedMessage string = "User joined"
	// UserInvitedMessage is a human-readable text message of the UserInvited activity
	UserInvitedMessage string = "User invited"
	// AccountCreatedMessage is a human-readable text message of the AccountCreated activity
	AccountCreatedMessage string = "Account created"
	// PeerRemovedByUserMessage is a human-readable text message of the PeerRemovedByUser activity
	PeerRemovedByUserMessage string = "Peer deleted"
	// RuleAddedMessage is a human-readable text message of the RuleAdded activity
	RuleAddedMessage string = "Rule added"
	// RuleRemovedMessage is a human-readable text message of the RuleRemoved activity
	RuleRemovedMessage string = "Rule deleted"
	// RuleUpdatedMessage is a human-readable text message of the RuleRemoved activity
	RuleUpdatedMessage string = "Rule updated"
	// PolicyAddedMessage is a human-readable text message of the PolicyAdded activity
	PolicyAddedMessage string = "Policy added"
	// PolicyRemovedMessage is a human-readable text message of the PolicyRemoved activity
	PolicyRemovedMessage string = "Policy deleted"
	// PolicyUpdatedMessage is a human-readable text message of the PolicyRemoved activity
	PolicyUpdatedMessage string = "Policy updated"
	// SetupKeyCreatedMessage is a human-readable text message of the SetupKeyCreated activity
	SetupKeyCreatedMessage string = "Setup key created"
	// SetupKeyUpdatedMessage is a human-readable text message of the SetupKeyUpdated activity
	SetupKeyUpdatedMessage string = "Setup key updated"
	// SetupKeyRevokedMessage is a human-readable text message of the SetupKeyRevoked activity
	SetupKeyRevokedMessage string = "Setup key revoked"
	// SetupKeyOverusedMessage is a human-readable text message of the SetupKeyOverused activity
	SetupKeyOverusedMessage string = "Setup key overused"
	// GroupCreatedMessage is a human-readable text message of the GroupCreated activity
	GroupCreatedMessage string = "Group created"
	// GroupUpdatedMessage is a human-readable text message of the GroupUpdated activity
	GroupUpdatedMessage string = "Group updated"
	// GroupAddedToPeerMessage is a human-readable text message of the GroupAddedToPeer activity
	GroupAddedToPeerMessage string = "Group added to peer"
	// GroupRemovedFromPeerMessage is a human-readable text message of the GroupRemovedFromPeer activity
	GroupRemovedFromPeerMessage string = "Group removed from peer"
	// GroupAddedToUserMessage is a human-readable text message of the GroupAddedToUser activity
	GroupAddedToUserMessage string = "Group added to user"
	// GroupRemovedFromUserMessage is a human-readable text message of the GroupRemovedFromUser activity
	GroupRemovedFromUserMessage string = "Group removed from user"
	// UserRoleUpdatedMessage is a human-readable text message of the UserRoleUpdatedMessage activity
	UserRoleUpdatedMessage string = "User role updated"
	// GroupAddedToSetupKeyMessage is a human-readable text message of the GroupAddedToSetupKey activity
	GroupAddedToSetupKeyMessage string = "Group added to setup key"
	// GroupRemovedFromSetupKeyMessage is a human-readable text message of the GroupRemovedFromSetupKey activity
	GroupRemovedFromSetupKeyMessage string = "Group removed from user setup key"
	// GroupAddedToDisabledManagementGroupsMessage is a human-readable text message of the GroupAddedToDisabledManagementGroups activity
	GroupAddedToDisabledManagementGroupsMessage string = "Group added to disabled management DNS setting"
	// GroupRemovedFromDisabledManagementGroupsMessage is a human-readable text message of the GroupRemovedFromDisabledManagementGroups activity
	GroupRemovedFromDisabledManagementGroupsMessage string = "Group removed from disabled management DNS setting"
	// RouteCreatedMessage is a human-readable text message of the RouteCreated activity
	RouteCreatedMessage string = "Route created"
	// RouteRemovedMessage is a human-readable text message of the RouteRemoved activity
	RouteRemovedMessage string = "Route deleted"
	// RouteUpdatedMessage is a human-readable text message of the RouteUpdated activity
	RouteUpdatedMessage string = "Route updated"
	// PeerSSHEnabledMessage is a human-readable text message of the PeerSSHEnabled activity
	PeerSSHEnabledMessage string = "Peer SSH server enabled"
	// PeerSSHDisabledMessage is a human-readable text message of the PeerSSHDisabled activity
	PeerSSHDisabledMessage string = "Peer SSH server disabled"
	// PeerRenamedMessage is a human-readable text message of the PeerRenamed activity
	PeerRenamedMessage string = "Peer renamed"
	// PeerLoginExpirationDisabledMessage is a human-readable text message of the PeerLoginExpirationDisabled activity
	PeerLoginExpirationDisabledMessage string = "Peer login expiration disabled"
	// PeerLoginExpirationEnabledMessage is a human-readable text message of the PeerLoginExpirationEnabled activity
	PeerLoginExpirationEnabledMessage string = "Peer login expiration enabled"
	// NameserverGroupCreatedMessage is a human-readable text message of the NameserverGroupCreated activity
	NameserverGroupCreatedMessage string = "Nameserver group created"
	// NameserverGroupDeletedMessage is a human-readable text message of the NameserverGroupDeleted activity
	NameserverGroupDeletedMessage string = "Nameserver group deleted"
	// NameserverGroupUpdatedMessage is a human-readable text message of the NameserverGroupUpdated activity
	NameserverGroupUpdatedMessage string = "Nameserver group updated"
	// AccountPeerLoginExpirationEnabledMessage is a human-readable text message of the AccountPeerLoginExpirationEnabled activity
	AccountPeerLoginExpirationEnabledMessage string = "Peer login expiration enabled for the account"
	// AccountPeerLoginExpirationDisabledMessage is a human-readable text message of the AccountPeerLoginExpirationDisabled activity
	AccountPeerLoginExpirationDisabledMessage string = "Peer login expiration disabled for the account"
	// AccountPeerLoginExpirationDurationUpdatedMessage is a human-readable text message of the AccountPeerLoginExpirationDurationUpdated activity
	AccountPeerLoginExpirationDurationUpdatedMessage string = "Peer login expiration duration updated"
	// PersonalAccessTokenCreatedMessage is a human-readable text message of the PersonalAccessTokenCreated activity
	PersonalAccessTokenCreatedMessage string = "Personal access token created"
	// PersonalAccessTokenDeletedMessage is a human-readable text message of the PersonalAccessTokenDeleted activity
	PersonalAccessTokenDeletedMessage string = "Personal access token deleted"
	// ServiceUserCreatedMessage is a human-readable text message of the ServiceUserCreated activity
	ServiceUserCreatedMessage string = "Service user created"
	// ServiceUserDeletedMessage is a human-readable text message of the ServiceUserDeleted activity
	ServiceUserDeletedMessage string = "Service user deleted"
)

// Activity that triggered an Event
type Activity int

// Message returns a string representation of an activity
func (a Activity) Message() string {
	switch a {
	case PeerAddedByUser:
		return PeerAddedByUserMessage
	case PeerRemovedByUser:
		return PeerRemovedByUserMessage
	case PeerAddedWithSetupKey:
		return PeerAddedWithSetupKeyMessage
	case UserJoined:
		return UserJoinedMessage
	case UserInvited:
		return UserInvitedMessage
	case AccountCreated:
		return AccountCreatedMessage
	case RuleAdded:
		return RuleAddedMessage
	case RuleRemoved:
		return RuleRemovedMessage
	case RuleUpdated:
		return RuleUpdatedMessage
	case PolicyAdded:
		return PolicyAddedMessage
	case PolicyRemoved:
		return PolicyRemovedMessage
	case PolicyUpdated:
		return PolicyUpdatedMessage
	case SetupKeyCreated:
		return SetupKeyCreatedMessage
	case SetupKeyUpdated:
		return SetupKeyUpdatedMessage
	case SetupKeyRevoked:
		return SetupKeyRevokedMessage
	case SetupKeyOverused:
		return SetupKeyOverusedMessage
	case GroupCreated:
		return GroupCreatedMessage
	case GroupUpdated:
		return GroupUpdatedMessage
	case GroupAddedToPeer:
		return GroupAddedToPeerMessage
	case GroupRemovedFromPeer:
		return GroupRemovedFromPeerMessage
	case GroupRemovedFromUser:
		return GroupRemovedFromUserMessage
	case GroupAddedToUser:
		return GroupAddedToUserMessage
	case UserRoleUpdated:
		return UserRoleUpdatedMessage
	case GroupAddedToSetupKey:
		return GroupAddedToSetupKeyMessage
	case GroupRemovedFromSetupKey:
		return GroupRemovedFromSetupKeyMessage
	case GroupAddedToDisabledManagementGroups:
		return GroupAddedToDisabledManagementGroupsMessage
	case GroupRemovedFromDisabledManagementGroups:
		return GroupRemovedFromDisabledManagementGroupsMessage
	case RouteCreated:
		return RouteCreatedMessage
	case RouteRemoved:
		return RouteRemovedMessage
	case RouteUpdated:
		return RouteUpdatedMessage
	case PeerSSHEnabled:
		return PeerSSHEnabledMessage
	case PeerSSHDisabled:
		return PeerSSHDisabledMessage
	case PeerLoginExpirationEnabled:
		return PeerLoginExpirationEnabledMessage
	case PeerLoginExpirationDisabled:
		return PeerLoginExpirationDisabledMessage
	case PeerRenamed:
		return PeerRenamedMessage
	case NameserverGroupCreated:
		return NameserverGroupCreatedMessage
	case NameserverGroupDeleted:
		return NameserverGroupDeletedMessage
	case NameserverGroupUpdated:
		return NameserverGroupUpdatedMessage
	case AccountPeerLoginExpirationEnabled:
		return AccountPeerLoginExpirationEnabledMessage
	case AccountPeerLoginExpirationDisabled:
		return AccountPeerLoginExpirationDisabledMessage
	case AccountPeerLoginExpirationDurationUpdated:
		return AccountPeerLoginExpirationDurationUpdatedMessage
	case PersonalAccessTokenCreated:
		return PersonalAccessTokenCreatedMessage
	case PersonalAccessTokenDeleted:
		return PersonalAccessTokenDeletedMessage
	case ServiceUserCreated:
		return ServiceUserCreatedMessage
	case ServiceUserDeleted:
		return ServiceUserDeletedMessage
	default:
		return "UNKNOWN_ACTIVITY"
	}
}

// StringCode returns a string code of the activity
func (a Activity) StringCode() string {
	switch a {
	case PeerAddedByUser:
		return "user.peer.add"
	case PeerRemovedByUser:
		return "user.peer.delete"
	case PeerAddedWithSetupKey:
		return "setupkey.peer.add"
	case UserJoined:
		return "user.join"
	case UserInvited:
		return "user.invite"
	case AccountCreated:
		return "account.create"
	case RuleAdded:
		return "rule.add"
	case RuleRemoved:
		return "rule.delete"
	case RuleUpdated:
		return "rule.update"
	case PolicyAdded:
		return "policy.add"
	case PolicyRemoved:
		return "policy.delete"
	case PolicyUpdated:
		return "policy.update"
	case SetupKeyCreated:
		return "setupkey.add"
	case SetupKeyRevoked:
		return "setupkey.revoke"
	case SetupKeyOverused:
		return "setupkey.overuse"
	case SetupKeyUpdated:
		return "setupkey.update"
	case GroupCreated:
		return "group.add"
	case GroupUpdated:
		return "group.update"
	case GroupRemovedFromPeer:
		return "peer.group.delete"
	case GroupAddedToPeer:
		return "peer.group.add"
	case GroupAddedToUser:
		return "user.group.add"
	case GroupRemovedFromUser:
		return "user.group.delete"
	case UserRoleUpdated:
		return "user.role.update"
	case GroupAddedToSetupKey:
		return "setupkey.group.add"
	case GroupRemovedFromSetupKey:
		return "setupkey.group.delete"
	case GroupAddedToDisabledManagementGroups:
		return "dns.setting.disabled.management.group.add"
	case GroupRemovedFromDisabledManagementGroups:
		return "dns.setting.disabled.management.group.delete"
	case RouteCreated:
		return "route.add"
	case RouteRemoved:
		return "route.delete"
	case RouteUpdated:
		return "route.update"
	case PeerRenamed:
		return "peer.rename"
	case PeerSSHEnabled:
		return "peer.ssh.enable"
	case PeerSSHDisabled:
		return "peer.ssh.disable"
	case PeerLoginExpirationDisabled:
		return "peer.login.expiration.disable"
	case PeerLoginExpirationEnabled:
		return "peer.login.expiration.enable"
	case NameserverGroupCreated:
		return "nameserver.group.add"
	case NameserverGroupDeleted:
		return "nameserver.group.delete"
	case NameserverGroupUpdated:
		return "nameserver.group.update"
	case AccountPeerLoginExpirationDurationUpdated:
		return "account.setting.peer.login.expiration.update"
	case AccountPeerLoginExpirationEnabled:
		return "account.setting.peer.login.expiration.enable"
	case AccountPeerLoginExpirationDisabled:
		return "account.setting.peer.login.expiration.disable"
	case PersonalAccessTokenCreated:
		return "personal.access.token.create"
	case PersonalAccessTokenDeleted:
		return "personal.access.token.delete"
	case ServiceUserCreated:
		return "service.user.create"
	case ServiceUserDeleted:
		return "service.user.delete"
	default:
		return "UNKNOWN_ACTIVITY"
	}
}
