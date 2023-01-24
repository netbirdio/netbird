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
)

const (
	// PeerAddedByUserMessage is a human-readable text message of the PeerAddedByUser activity
	PeerAddedByUserMessage string = "Peer added"
	// PeerAddedWithSetupKeyMessage is a human-readable text message of the PeerAddedWithSetupKey activity
	PeerAddedWithSetupKeyMessage = PeerAddedByUserMessage
	//UserJoinedMessage is a human-readable text message of the UserJoined activity
	UserJoinedMessage string = "User joined"
	//UserInvitedMessage is a human-readable text message of the UserInvited activity
	UserInvitedMessage string = "User invited"
	//AccountCreatedMessage is a human-readable text message of the AccountCreated activity
	AccountCreatedMessage string = "Account created"
	// PeerRemovedByUserMessage is a human-readable text message of the PeerRemovedByUser activity
	PeerRemovedByUserMessage string = "Peer deleted"
	// RuleAddedMessage is a human-readable text message of the RuleAdded activity
	RuleAddedMessage string = "Rule added"
	// RuleRemovedMessage is a human-readable text message of the RuleRemoved activity
	RuleRemovedMessage string = "Rule deleted"
	// RuleUpdatedMessage is a human-readable text message of the RuleRemoved activity
	RuleUpdatedMessage string = "Rule updated"
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
	default:
		return "UNKNOWN_ACTIVITY"
	}
}
