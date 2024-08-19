package server

import (
	"context"
	_ "embed"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
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
	// PolicyRuleFlowDirect allows traffic from source to destination
	PolicyRuleFlowDirect = PolicyRuleDirection("direct")
	// PolicyRuleFlowBidirect allows traffic to both directions
	PolicyRuleFlowBidirect = PolicyRuleDirection("bidirect")
)

const (
	// DefaultRuleName is a name for the Default rule that is created for every account
	DefaultRuleName = "Default"
	// DefaultRuleDescription is a description for the Default rule that is created for every account
	DefaultRuleDescription = "This is a default rule that allows connections between all the resources"
	// DefaultPolicyName is a name for the Default policy that is created for every account
	DefaultPolicyName = "Default"
	// DefaultPolicyDescription is a description for the Default policy that is created for every account
	DefaultPolicyDescription = "This is a default policy that allows connections between all the resources"
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

// RulePortRange represents a range of ports for a firewall rule.
type RulePortRange struct {
	Start uint16
	End   uint16
}

// PolicyRule is the metadata of the policy
type PolicyRule struct {
	// ID of the policy rule
	ID string `gorm:"primaryKey"`

	// PolicyID is a reference to Policy that this object belongs
	PolicyID string `json:"-" gorm:"index"`

	// Name of the rule visible in the UI
	Name string

	// Description of the rule visible in the UI
	Description string

	// Enabled status of rule in the system
	Enabled bool

	// Action policy accept or drops packets
	Action PolicyTrafficActionType

	// Destinations policy destination groups
	Destinations []string `gorm:"serializer:json"`

	// Sources policy source groups
	Sources []string `gorm:"serializer:json"`

	// Bidirectional define if the rule is applicable in both directions, sources, and destinations
	Bidirectional bool

	// Protocol type of the traffic
	Protocol PolicyRuleProtocolType

	// Ports or it ranges list
	Ports []string `gorm:"serializer:json"`

	// PortRanges a list of port ranges.
	PortRanges []RulePortRange `gorm:"serializer:json"`
}

// Copy returns a copy of a policy rule
func (pm *PolicyRule) Copy() *PolicyRule {
	rule := &PolicyRule{
		ID:            pm.ID,
		Name:          pm.Name,
		Description:   pm.Description,
		Enabled:       pm.Enabled,
		Action:        pm.Action,
		Destinations:  make([]string, len(pm.Destinations)),
		Sources:       make([]string, len(pm.Sources)),
		Bidirectional: pm.Bidirectional,
		Protocol:      pm.Protocol,
		Ports:         make([]string, len(pm.Ports)),
		PortRanges:    make([]RulePortRange, len(pm.PortRanges)),
	}
	copy(rule.Destinations, pm.Destinations)
	copy(rule.Sources, pm.Sources)
	copy(rule.Ports, pm.Ports)
	copy(rule.PortRanges, pm.PortRanges)
	return rule
}

// Policy of the Rego query
type Policy struct {
	// ID of the policy'
	ID string `gorm:"primaryKey"`

	// AccountID is a reference to Account that this object belongs
	AccountID string `json:"-" gorm:"index"`

	// Name of the Policy
	Name string

	// Description of the policy visible in the UI
	Description string

	// Enabled status of the policy
	Enabled bool

	// Rules of the policy
	Rules []*PolicyRule `gorm:"foreignKey:PolicyID;references:id;constraint:OnDelete:CASCADE;"`

	// SourcePostureChecks are ID references to Posture checks for policy source groups
	SourcePostureChecks []string `gorm:"serializer:json"`
}

// Copy returns a copy of the policy.
func (p *Policy) Copy() *Policy {
	c := &Policy{
		ID:                  p.ID,
		Name:                p.Name,
		Description:         p.Description,
		Enabled:             p.Enabled,
		Rules:               make([]*PolicyRule, len(p.Rules)),
		SourcePostureChecks: make([]string, len(p.SourcePostureChecks)),
	}
	for i, r := range p.Rules {
		c.Rules[i] = r.Copy()
	}
	copy(c.SourcePostureChecks, p.SourcePostureChecks)
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
func (a *Account) getPeerConnectionResources(ctx context.Context, peerID string, validatedPeersMap map[string]struct{}) ([]*nbpeer.Peer, []*FirewallRule) {
	generateResources, getAccumulatedResources := a.connResourcesGenerator(ctx)
	for _, policy := range a.Policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			sourcePeers, peerInSources := a.getAllPeersFromGroups(ctx, rule.Sources, peerID, policy.SourcePostureChecks, validatedPeersMap)
			destinationPeers, peerInDestinations := a.getAllPeersFromGroups(ctx, rule.Destinations, peerID, nil, validatedPeersMap)

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
func (a *Account) connResourcesGenerator(ctx context.Context) (func(*PolicyRule, []*nbpeer.Peer, int), func() ([]*nbpeer.Peer, []*FirewallRule)) {
	rulesExists := make(map[string]struct{})
	peersExists := make(map[string]struct{})
	rules := make([]*FirewallRule, 0)
	peers := make([]*nbpeer.Peer, 0)

	all, err := a.GetGroupAll()
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get group all: %v", err)
		all = &nbgroup.Group{}
	}

	return func(rule *PolicyRule, groupPeers []*nbpeer.Peer, direction int) {
			isAll := (len(all.Peers) - 1) == len(groupPeers)
			for _, peer := range groupPeers {
				if peer == nil {
					continue
				}

				if _, ok := peersExists[peer.ID]; !ok {
					peers = append(peers, peer)
					peersExists[peer.ID] = struct{}{}
				}

				fr := FirewallRule{
					PeerIP:    peer.IP.String(),
					Direction: direction,
					Action:    string(rule.Action),
					Protocol:  string(rule.Protocol),
				}

				if isAll {
					fr.PeerIP = "0.0.0.0"
				}

				ruleID := rule.ID + fr.PeerIP + strconv.Itoa(direction) +
					fr.Protocol + fr.Action + strings.Join(rule.Ports, ",")
				if _, ok := rulesExists[ruleID]; ok {
					continue
				}
				rulesExists[ruleID] = struct{}{}

				if len(rule.Ports) == 0 {
					rules = append(rules, &fr)
					continue
				}

				for _, port := range rule.Ports {
					pr := fr // clone rule and add set new port
					pr.Port = port
					rules = append(rules, &pr)
				}
			}
		}, func() ([]*nbpeer.Peer, []*FirewallRule) {
			return peers, rules
		}
}

// GetPolicy from the store
func (am *DefaultAccountManager) GetPolicy(ctx context.Context, accountID, policyID, userID string) (*Policy, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !(user.HasAdminPower() || user.IsServiceUser) {
		return nil, status.Errorf(status.PermissionDenied, "only users with admin power are allowed to view policies")
	}

	for _, policy := range account.Policies {
		if policy.ID == policyID {
			return policy, nil
		}
	}

	return nil, status.Errorf(status.NotFound, "policy with ID %s not found", policyID)
}

// SavePolicy in the store
func (am *DefaultAccountManager) SavePolicy(ctx context.Context, accountID, userID string, policy *Policy) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	exists := am.savePolicy(account, policy)

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return err
	}

	action := activity.PolicyAdded
	if exists {
		action = activity.PolicyUpdated
	}
	am.StoreEvent(ctx, userID, policy.ID, accountID, action, policy.EventMeta())

	am.updateAccountPeers(ctx, account)

	return nil
}

// DeletePolicy from the store
func (am *DefaultAccountManager) DeletePolicy(ctx context.Context, accountID, policyID, userID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	policy, err := am.deletePolicy(account, policyID)
	if err != nil {
		return err
	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, policy.ID, accountID, activity.PolicyRemoved, policy.EventMeta())

	am.updateAccountPeers(ctx, account)

	return nil
}

// ListPolicies from the store
func (am *DefaultAccountManager) ListPolicies(ctx context.Context, accountID, userID string) ([]*Policy, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !(user.HasAdminPower() || user.IsServiceUser) {
		return nil, status.Errorf(status.PermissionDenied, "only users with admin power can view policies")
	}

	return account.Policies, nil
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

func toProtocolFirewallRules(rules []*FirewallRule) []*proto.FirewallRule {
	result := make([]*proto.FirewallRule, len(rules))
	for i := range rules {
		rule := rules[i]

		result[i] = &proto.FirewallRule{
			PeerIP:    rule.PeerIP,
			Direction: getProtoDirection(rule.Direction),
			Action:    getProtoAction(rule.Action),
			Protocol:  getProtoProtocol(rule.Protocol),
			Port:      rule.Port,
		}
	}
	return result
}

// getAllPeersFromGroups for given peer ID and list of groups
//
// Returns a list of peers from specified groups that pass specified posture checks
// and a boolean indicating if the supplied peer ID exists within these groups.
//
// Important: Posture checks are applicable only to source group peers,
// for destination group peers, call this method with an empty list of sourcePostureChecksIDs
func (a *Account) getAllPeersFromGroups(ctx context.Context, groups []string, peerID string, sourcePostureChecksIDs []string, validatedPeersMap map[string]struct{}) ([]*nbpeer.Peer, bool) {
	peerInGroups := false
	filteredPeers := make([]*nbpeer.Peer, 0, len(groups))
	for _, g := range groups {
		group, ok := a.Groups[g]
		if !ok {
			continue
		}

		for _, p := range group.Peers {
			peer, ok := a.Peers[p]
			if !ok || peer == nil {
				continue
			}

			// validate the peer based on policy posture checks applied
			isValid := a.validatePostureChecksOnPeer(ctx, sourcePostureChecksIDs, peer.ID)
			if !isValid {
				continue
			}

			if _, ok := validatedPeersMap[peer.ID]; !ok {
				continue
			}

			if peer.ID == peerID {
				peerInGroups = true
				continue
			}

			filteredPeers = append(filteredPeers, peer)
		}
	}
	return filteredPeers, peerInGroups
}

// validatePostureChecksOnPeer validates the posture checks on a peer
func (a *Account) validatePostureChecksOnPeer(ctx context.Context, sourcePostureChecksID []string, peerID string) bool {
	peer, ok := a.Peers[peerID]
	if !ok && peer == nil {
		return false
	}

	for _, postureChecksID := range sourcePostureChecksID {
		postureChecks := a.getPostureChecks(postureChecksID)
		if postureChecks == nil {
			continue
		}

		for _, check := range postureChecks.GetChecks() {
			isValid, err := check.Check(ctx, *peer)
			if err != nil {
				log.WithContext(ctx).Debugf("an error occurred check %s: on peer: %s :%s", check.Name(), peer.ID, err.Error())
			}
			if !isValid {
				return false
			}
		}
	}
	return true
}

func (a *Account) getPostureChecks(postureChecksID string) *posture.Checks {
	for _, postureChecks := range a.PostureChecks {
		if postureChecks.ID == postureChecksID {
			return postureChecks
		}
	}
	return nil
}
