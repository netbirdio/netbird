package types

import (
	"context"
	"strconv"

	log "github.com/sirupsen/logrus"

	auth "github.com/netbirdio/netbird/shared/sessionauth"
)

// vncInternalPort is the internal port the VNC server listens on (behind DNAT from 5900).
const vncInternalPort = 25900

// PeerConnResolveState carries the in-progress maps mutated by per-rule
// resolution while walking an account's policies.
type PeerConnResolveState struct {
	AuthorizedUsers    map[string]map[string]struct{}
	VNCAuthorizedUsers map[string]map[string]struct{}
	VNCSessionPubKeys  []VNCSessionPubKey
	SSHEnabled         bool
}

// NewPeerConnResolveState returns a state with its maps allocated.
func NewPeerConnResolveState() *PeerConnResolveState {
	return &PeerConnResolveState{
		AuthorizedUsers:    make(map[string]map[string]struct{}),
		VNCAuthorizedUsers: make(map[string]map[string]struct{}),
	}
}

// VNCSessionPubKey carries an ephemeral X25519 static public key the
// dashboard registered via temporary-access. The daemon uses it as the
// allowed-client side of a Noise_IK handshake; a successful handshake
// authenticates the connection as UserID.
type VNCSessionPubKey struct {
	// PubKey is the base64-encoded 32-byte X25519 public key.
	PubKey string
	// UserID is the unhashed user identity the pubkey authenticates as.
	UserID string
	// DisplayName is a human-readable label for UserID, used by the host
	// peer's approval prompt. Empty when not provided.
	DisplayName string
}

// RuleAuthCallbacks lets Account and NetworkMapComponents share the per-rule
// direction-and-auth logic while keeping their own context/state plumbing for
// authorized-user collection and allowed-user lookups.
type RuleAuthCallbacks struct {
	CollectSSHUsers   func(*PolicyRule, map[string]map[string]struct{})
	CollectVNCUsers   func(*PolicyRule, map[string]map[string]struct{})
	GetAllowedUserIDs func() map[string]struct{}
}

// ApplyResolvedRuleToState emits firewall rules in the rule's directions and
// records authorized users into state according to the rule's protocol. The
// callbacks supply the auth-collection behaviour specific to the calling
// resolver (Account vs NetworkMapComponents), which also decide the peer
// representation the resource generator works with.
func ApplyResolvedRuleToState[P any](
	rule *PolicyRule,
	sourcePeers []P,
	destPeers []P,
	peerInSources bool,
	peerInDestinations bool,
	targetPeerSSHEnabled bool,
	generateResources func(*PolicyRule, []P, int),
	cb RuleAuthCallbacks,
	state *PeerConnResolveState,
) {
	emitRuleDirections(rule, sourcePeers, destPeers, peerInSources, peerInDestinations, generateResources)

	receivingPeer := peerInDestinations || (rule.Bidirectional && peerInSources)
	switch {
	case rule.Protocol == PolicyRuleProtocolNetbirdSSH:
		if !receivingPeer {
			return
		}
		state.SSHEnabled = true
		cb.CollectSSHUsers(rule, state.AuthorizedUsers)
	case rule.Protocol == PolicyRuleProtocolNetbirdVNC:
		cb.handleVNCRule(rule, peerInSources, peerInDestinations, state)
	case PolicyRuleImpliesLegacySSH(rule) && targetPeerSSHEnabled:
		if !receivingPeer {
			return
		}
		state.SSHEnabled = true
		MergeWildcardUsers(state.AuthorizedUsers, cb.GetAllowedUserIDs())
	}
}

// handleVNCRule collects VNC authorized users and session pubkeys for a VNC
// policy rule. Bidirectional rules grant access in both directions, so a
// peer that appears in the rule's sources also needs the SessionPubKey
// pushed (otherwise the Noise_IK handshake against that peer would fail
// because its authorizer wouldn't know the client's static key).
func (cb RuleAuthCallbacks) handleVNCRule(rule *PolicyRule, peerInSources, peerInDestinations bool, state *PeerConnResolveState) {
	receivingPeer := peerInDestinations || (rule.Bidirectional && peerInSources)
	if !receivingPeer {
		return
	}
	cb.CollectVNCUsers(rule, state.VNCAuthorizedUsers)
	if rule.SessionPubKey != "" && rule.AuthorizedUser != "" {
		state.VNCSessionPubKeys = append(state.VNCSessionPubKeys, VNCSessionPubKey{
			PubKey:      rule.SessionPubKey,
			UserID:      rule.AuthorizedUser,
			DisplayName: rule.SessionDisplayName,
		})
	}
}

// MergeWildcardUsers adds every user in users to the wildcard local-user entry
// of dst, allocating the entry on demand.
func MergeWildcardUsers(dst map[string]map[string]struct{}, users map[string]struct{}) {
	if dst[auth.Wildcard] == nil {
		dst[auth.Wildcard] = make(map[string]struct{})
	}
	for userID := range users {
		dst[auth.Wildcard][userID] = struct{}{}
	}
}

// emitRuleDirections dispatches generateResources for each direction the rule
// applies in for the target peer.
func emitRuleDirections[P any](
	rule *PolicyRule,
	sourcePeers []P,
	destPeers []P,
	peerInSources bool,
	peerInDestinations bool,
	generateResources func(*PolicyRule, []P, int),
) {
	if rule.Bidirectional {
		if peerInSources {
			generateResources(rule, destPeers, FirewallRuleDirectionIN)
		}
		if peerInDestinations {
			generateResources(rule, sourcePeers, FirewallRuleDirectionOUT)
		}
	}
	if peerInSources {
		generateResources(rule, destPeers, FirewallRuleDirectionOUT)
	}
	if peerInDestinations {
		generateResources(rule, sourcePeers, FirewallRuleDirectionIN)
	}
}

// MergeAuthorizedGroupUsers expands AuthorizedGroups (group ID to local user
// list) into target, mapping each local user to the set of user IDs in the
// referenced group. Used by both Account and NetworkMapComponents auth
// resolution paths.
func MergeAuthorizedGroupUsers(
	ctx context.Context,
	authorizedGroups map[string][]string,
	groupIDToUserIDs map[string][]string,
	target map[string]map[string]struct{},
) {
	for groupID, localUsers := range authorizedGroups {
		userIDs, ok := groupIDToUserIDs[groupID]
		if !ok {
			log.WithContext(ctx).Tracef("no user IDs found for group ID %s", groupID)
			continue
		}
		if len(localUsers) == 0 {
			localUsers = []string{auth.Wildcard}
		}
		assignUsersToLocal(target, localUsers, userIDs)
	}
}

// assignUsersToLocal adds each userID to target[localUser] for every entry in
// localUsers, allocating the inner set on demand.
func assignUsersToLocal(target map[string]map[string]struct{}, localUsers, userIDs []string) {
	for _, localUser := range localUsers {
		if target[localUser] == nil {
			target[localUser] = make(map[string]struct{})
		}
		for _, userID := range userIDs {
			target[localUser][userID] = struct{}{}
		}
	}
}

// EnsureWildcardUser ensures the wildcard local-user entry exists in target
// and adds the given authorized user to it.
func EnsureWildcardUser(target map[string]map[string]struct{}, authorizedUser string) {
	if target[auth.Wildcard] == nil {
		target[auth.Wildcard] = make(map[string]struct{})
	}
	target[auth.Wildcard][authorizedUser] = struct{}{}
}

// NormalizePolicyRuleProtocol maps NetBird virtual protocols (netbird-ssh,
// netbird-vnc) to TCP for the on-the-wire firewall view. For NetbirdVNC the
// rule is also scoped to the embedded VNC port so a VNC-only rule doesn't
// degrade into an unscoped TCP allow when the user left Ports empty.
// Returns the effective rule (possibly a shallow copy with Ports overridden)
// and the resulting protocol.
func NormalizePolicyRuleProtocol(rule *PolicyRule) (*PolicyRule, PolicyRuleProtocolType) {
	switch rule.Protocol {
	case PolicyRuleProtocolNetbirdSSH:
		return rule, PolicyRuleProtocolTCP
	case PolicyRuleProtocolNetbirdVNC:
		if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
			scoped := *rule
			scoped.Ports = []string{strconv.Itoa(vncInternalPort)}
			return &scoped, PolicyRuleProtocolTCP
		}
		return rule, PolicyRuleProtocolTCP
	default:
		return rule, rule.Protocol
	}
}
