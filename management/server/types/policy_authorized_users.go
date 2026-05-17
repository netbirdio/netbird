package types

import (
	"context"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/ssh/auth"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

// peerConnResolveState carries the in-progress maps mutated by per-rule
// resolution while walking an account's policies.
type peerConnResolveState struct {
	authorizedUsers    map[string]map[string]struct{}
	vncAuthorizedUsers map[string]map[string]struct{}
	sshEnabled         bool
}

// ruleAuthCallbacks lets Account and NetworkMapComponents share the per-rule
// direction-and-auth logic while keeping their own context/state plumbing for
// authorized-user collection and allowed-user lookups.
type ruleAuthCallbacks struct {
	collectSSHUsers   func(*PolicyRule, map[string]map[string]struct{})
	collectVNCUsers   func(*PolicyRule, map[string]map[string]struct{})
	getAllowedUserIDs func() map[string]struct{}
}

// applyResolvedRuleToState emits firewall rules in the rule's directions and
// records authorized users into state according to the rule's protocol. The
// callbacks supply the auth-collection behaviour specific to the calling
// resolver (Account vs NetworkMapComponents).
func applyResolvedRuleToState(
	rule *PolicyRule,
	sourcePeers []*nbpeer.Peer,
	destPeers []*nbpeer.Peer,
	peerInSources bool,
	peerInDestinations bool,
	targetPeerSSHEnabled bool,
	generateResources func(*PolicyRule, []*nbpeer.Peer, int),
	cb ruleAuthCallbacks,
	state *peerConnResolveState,
) {
	emitRuleDirections(rule, sourcePeers, destPeers, peerInSources, peerInDestinations, generateResources)

	switch {
	case rule.Protocol == PolicyRuleProtocolNetbirdSSH:
		if !peerInDestinations {
			return
		}
		state.sshEnabled = true
		cb.collectSSHUsers(rule, state.authorizedUsers)
	case rule.Protocol == PolicyRuleProtocolNetbirdVNC:
		// VNC bidirectional rules grant access in both directions.
		if !peerInDestinations && !(rule.Bidirectional && peerInSources) {
			return
		}
		cb.collectVNCUsers(rule, state.vncAuthorizedUsers)
	case policyRuleImpliesLegacySSH(rule) && targetPeerSSHEnabled:
		if !peerInDestinations {
			return
		}
		state.sshEnabled = true
		if state.authorizedUsers[auth.Wildcard] == nil {
			state.authorizedUsers[auth.Wildcard] = make(map[string]struct{})
		}
		for userID := range cb.getAllowedUserIDs() {
			state.authorizedUsers[auth.Wildcard][userID] = struct{}{}
		}
	}
}

// emitRuleDirections dispatches generateResources for each direction the rule
// applies in for the target peer.
func emitRuleDirections(
	rule *PolicyRule,
	sourcePeers []*nbpeer.Peer,
	destPeers []*nbpeer.Peer,
	peerInSources bool,
	peerInDestinations bool,
	generateResources func(*PolicyRule, []*nbpeer.Peer, int),
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

// mergeAuthorizedGroupUsers expands AuthorizedGroups (group ID to local user
// list) into target, mapping each local user to the set of user IDs in the
// referenced group. Used by both Account and NetworkMapComponents auth
// resolution paths.
func mergeAuthorizedGroupUsers(
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

// ensureWildcardUser ensures the wildcard local-user entry exists in target
// and adds the given authorized user to it.
func ensureWildcardUser(target map[string]map[string]struct{}, authorizedUser string) {
	if target[auth.Wildcard] == nil {
		target[auth.Wildcard] = make(map[string]struct{})
	}
	target[auth.Wildcard][authorizedUser] = struct{}{}
}

// normalizePolicyRuleProtocol maps NetBird virtual protocols (netbird-ssh,
// netbird-vnc) to TCP for the on-the-wire firewall view. For NetbirdVNC the
// rule is also scoped to the embedded VNC port so a VNC-only rule doesn't
// degrade into an unscoped TCP allow when the user left Ports empty.
// Returns the effective rule (possibly a shallow copy with Ports overridden)
// and the resulting protocol.
func normalizePolicyRuleProtocol(rule *PolicyRule) (*PolicyRule, PolicyRuleProtocolType) {
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
