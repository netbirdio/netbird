package server

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
)

// PolicyUpdateOperationType operation type
type PolicyUpdateOperationType int

// PolicyTrafficActionType action type for the firewall
type PolicyTrafficActionType string

// PolicyRuleProtocolType type of traffic
type PolicyRuleProtocolType string

// PolicyRuleDirection direction of traffic
type PolicyRuleDirection string

const (
	// PolicyTrafficActionAccept indicates that the traffic is accepted
	PolicyTrafficActionAccept = PolicyTrafficActionType("accept")
	// PolicyTrafficActionDrop indicates that the traffic is dropped
	PolicyTrafficActionDrop = PolicyTrafficActionType("drop")
)

const (
	// PolicyRuleProtocolALL type of traffic
	PolicyRuleProtocolALL = PolicyRuleProtocolType("all")
	// PolicyRuleProtocolTCP type of traffic
	PolicyRuleProtocolTCP = PolicyRuleProtocolType("tcp")
	// PolicyRuleProtocolUDP type of traffic
	PolicyRuleProtocolUDP = PolicyRuleProtocolType("udp")
	// PolicyRuleProtocolICMP type of traffic
	PolicyRuleProtocolICMP = PolicyRuleProtocolType("icmp")
)

const (
	// PolicyRuleFlowDirect allows trafic from source to destination
	PolicyRuleFlowDirect = PolicyRuleDirection("direct")
	// PolicyRuleFlowBidirect allows traffic to both directions
	PolicyRuleFlowBidirect = PolicyRuleDirection("bidirect")
)

const (
	firewallRuleDirectionIN  = 0
	firewallRuleDirectionOUT = 1
)

// PolicyUpdateOperation operation object with type and values to be applied
type PolicyUpdateOperation struct {
	Type   PolicyUpdateOperationType
	Values []string
}

// PolicyRule is the metadata of the policy
type PolicyRule struct {
	// ID of the policy rule
	ID string

	// Name of the rule visible in the UI
	Name string

	// Description of the rule visible in the UI
	Description string

	// Enabled status of rule in the system
	Enabled bool

	// Action policy accept or drops packets
	Action PolicyTrafficActionType

	// Destinations policy destination groups
	Destinations []string

	// Sources policy source groups
	Sources []string

	// Bidirectional define if the rule is applicable in both directions, sources, and destinations
	Bidirectional bool

	// Protocol type of the traffic
	Protocol PolicyRuleProtocolType

	// Ports or it ranges list
	Ports []string
}

// Copy returns a copy of a policy rule
func (pm *PolicyRule) Copy() *PolicyRule {
	return &PolicyRule{
		ID:            pm.ID,
		Name:          pm.Name,
		Description:   pm.Description,
		Enabled:       pm.Enabled,
		Action:        pm.Action,
		Destinations:  pm.Destinations[:],
		Sources:       pm.Sources[:],
		Bidirectional: pm.Bidirectional,
		Protocol:      pm.Protocol,
		Ports:         pm.Ports[:],
	}
}

// ToRule converts the PolicyRule to a legacy representation of the Rule (for backwards compatibility)
func (pm *PolicyRule) ToRule() *Rule {
	return &Rule{
		ID:          pm.ID,
		Name:        pm.Name,
		Description: pm.Description,
		Disabled:    !pm.Enabled,
		Flow:        TrafficFlowBidirect,
		Destination: pm.Destinations,
		Source:      pm.Sources,
	}
}

// Policy of the Rego query
type Policy struct {
	// ID of the policy
	ID string

	// Name of the Policy
	Name string

	// Description of the policy visible in the UI
	Description string

	// Enabled status of the policy
	Enabled bool

	// Rules of the policy
	Rules []*PolicyRule
}

// Copy returns a copy of the policy.
func (p *Policy) Copy() *Policy {
	c := &Policy{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Enabled:     p.Enabled,
	}
	for _, r := range p.Rules {
		c.Rules = append(c.Rules, r.Copy())
	}
	return c
}

// EventMeta returns activity event meta related to this policy
func (p *Policy) EventMeta() map[string]any {
	return map[string]any{"name": p.Name}
}

// UpgradeAndFix different version of policies to latest version
func (p *Policy) UpgradeAndFix() {
	for _, r := range p.Rules {
		// start migrate from version v0.20.3
		if r.Protocol == "" {
			r.Protocol = PolicyRuleProtocolALL
		}
		if r.Protocol == PolicyRuleProtocolALL && !r.Bidirectional {
			r.Bidirectional = true
		}
		// -- v0.20.4
	}
}

// FirewallRule is a rule of the firewall.
type FirewallRule struct {
	// PeerIP of the peer
	PeerIP string

	// Direction of the traffic
	Direction int

	// Action of the traffic
	Action string

	// Protocol of the traffic
	Protocol string

	// Port of the traffic
	Port string
}

// getPeerConnectionResources for a given peer
//
// This function returns the list of peers and firewall rules that are applicable to a given peer.
func (a *Account) getPeerConnectionResources(peerID string) ([]*Peer, []*FirewallRule) {
	generateResources, getAccumulatedResources := a.connResourcesGenerator()

	for _, policy := range a.Policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			sourcePeers, peerInSources := getAllPeersFromGroups(a, rule.Sources, peerID)
			destinationPeers, peerInDestinations := getAllPeersFromGroups(a, rule.Destinations, peerID)

			if rule.Bidirectional {
				if peerInSources {
					generateResources(rule, destinationPeers, firewallRuleDirectionIN)
				}
				if peerInDestinations {
					generateResources(rule, sourcePeers, firewallRuleDirectionOUT)
				}
			}

			if peerInSources {
				generateResources(rule, destinationPeers, firewallRuleDirectionOUT)
			}

			if peerInDestinations {
				generateResources(rule, sourcePeers, firewallRuleDirectionIN)
			}
		}
	}

	return getAccumulatedResources()
}

// connResourcesGenerator returns generator and accumulator function which returns the result of generator calls
//
// The generator function is used to generate the list of peers and firewall rules that are applicable to a given peer.
// It safe to call the generator function multiple times for same peer and different rules no duplicates will be
// generated. The accumulator function returns the result of all the generator calls.
func (a *Account) connResourcesGenerator() (func(*PolicyRule, []*Peer, int), func() ([]*Peer, []*FirewallRule)) {
	rulesExists := make(map[string]struct{})
	peersExists := make(map[string]struct{})
	rules := make([]*FirewallRule, 0)
	peers := make([]*Peer, 0)
	return func(rule *PolicyRule, groupPeers []*Peer, direction int) {
			for _, peer := range groupPeers {
				if _, ok := peersExists[peer.ID]; !ok {
					peers = append(peers, peer)
					peersExists[peer.ID] = struct{}{}
				}

				fwRule := FirewallRule{
					PeerIP:    peer.IP.String(),
					Direction: direction,
					Action:    string(rule.Action),
					Protocol:  string(rule.Protocol),
				}

				ruleID := fmt.Sprintf("%s%d", peer.ID+peer.IP.String(), direction)
				ruleID += string(rule.Protocol) + string(rule.Action) + strings.Join(rule.Ports, ",")
				if _, ok := rulesExists[ruleID]; ok {
					continue
				}
				rulesExists[ruleID] = struct{}{}

				if len(rule.Ports) == 0 {
					rules = append(rules, &fwRule)
					continue
				}

				for _, port := range rule.Ports {
					addRule := fwRule
					addRule.Port = port
					rules = append(rules, &addRule)
				}
			}
		}, func() ([]*Peer, []*FirewallRule) {
			return peers, rules
		}
}

// GetPolicy from the store
func (am *DefaultAccountManager) GetPolicy(accountID, policyID, userID string) (*Policy, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.IsAdmin() {
		return nil, status.Errorf(status.PermissionDenied, "only admins are allowed to view policies")
	}

	for _, policy := range account.Policies {
		if policy.ID == policyID {
			return policy, nil
		}
	}

	return nil, status.Errorf(status.NotFound, "policy with ID %s not found", policyID)
}

// SavePolicy in the store
func (am *DefaultAccountManager) SavePolicy(accountID, userID string, policy *Policy) error {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	exists := am.savePolicy(account, policy)

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	action := activity.PolicyAdded
	if exists {
		action = activity.PolicyUpdated
	}
	am.storeEvent(userID, policy.ID, accountID, action, policy.EventMeta())

	return am.updateAccountPeers(account)
}

// DeletePolicy from the store
func (am *DefaultAccountManager) DeletePolicy(accountID, policyID, userID string) error {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	policy, err := am.deletePolicy(account, policyID)
	if err != nil {
		return err
	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	am.storeEvent(userID, policy.ID, accountID, activity.PolicyRemoved, policy.EventMeta())

	return am.updateAccountPeers(account)
}

// ListPolicies from the store
func (am *DefaultAccountManager) ListPolicies(accountID, userID string) ([]*Policy, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.IsAdmin() {
		return nil, status.Errorf(status.PermissionDenied, "Only Administrators can view policies")
	}

	return account.Policies[:], nil
}

func (am *DefaultAccountManager) deletePolicy(account *Account, policyID string) (*Policy, error) {
	policyIdx := -1
	for i, policy := range account.Policies {
		if policy.ID == policyID {
			policyIdx = i
			break
		}
	}
	if policyIdx < 0 {
		return nil, status.Errorf(status.NotFound, "rule with ID %s doesn't exist", policyID)
	}

	policy := account.Policies[policyIdx]
	account.Policies = append(account.Policies[:policyIdx], account.Policies[policyIdx+1:]...)
	return policy, nil
}

func (am *DefaultAccountManager) savePolicy(account *Account, policy *Policy) (exists bool) {
	for i, p := range account.Policies {
		if p.ID == policy.ID {
			account.Policies[i] = policy
			exists = true
			break
		}
	}
	if !exists {
		account.Policies = append(account.Policies, policy)
	}
	return
}

func toProtocolFirewallRules(update []*FirewallRule) []*proto.FirewallRule {
	result := make([]*proto.FirewallRule, len(update))
	for i := range update {
		direction := proto.FirewallRule_IN
		if update[i].Direction == firewallRuleDirectionOUT {
			direction = proto.FirewallRule_OUT
		}
		action := proto.FirewallRule_ACCEPT
		if update[i].Action == string(PolicyTrafficActionDrop) {
			action = proto.FirewallRule_DROP
		}

		protocol := proto.FirewallRule_UNKNOWN
		switch PolicyRuleProtocolType(update[i].Protocol) {
		case PolicyRuleProtocolALL:
			protocol = proto.FirewallRule_ALL
		case PolicyRuleProtocolTCP:
			protocol = proto.FirewallRule_TCP
		case PolicyRuleProtocolUDP:
			protocol = proto.FirewallRule_UDP
		case PolicyRuleProtocolICMP:
			protocol = proto.FirewallRule_ICMP
		}

		result[i] = &proto.FirewallRule{
			PeerIP:    update[i].PeerIP,
			Direction: direction,
			Action:    action,
			Protocol:  protocol,
			Port:      update[i].Port,
		}
	}
	return result
}

// getAllPeersFromGroups for given peer ID and list of groups
//
// Returns list of peers and boolean indicating if peer is in any of the groups
func getAllPeersFromGroups(account *Account, groups []string, peerID string) ([]*Peer, bool) {
	peerInGroups := false
	filteredPeers := make([]*Peer, 0, len(groups))
	for _, g := range groups {
		group, ok := account.Groups[g]
		if !ok {
			continue
		}

		for _, p := range group.Peers {
			peer := account.Peers[p]
			if peer.ID == peerID {
				peerInGroups = true
				continue
			}

			filteredPeers = append(filteredPeers, peer)
		}
	}
	return filteredPeers, peerInGroups
}
