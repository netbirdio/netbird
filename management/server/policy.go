package server

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"strings"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"

	"github.com/open-policy-agent/opa/rego"
	log "github.com/sirupsen/logrus"
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

// PolicyUpdateOperation operation object with type and values to be applied
type PolicyUpdateOperation struct {
	Type   PolicyUpdateOperationType
	Values []string
}

//go:embed rego/default_policy_module.rego
var defaultPolicyModule string

//go:embed rego/default_policy.rego
var defaultPolicyText string

// defaultPolicyTemplate is a template to migrate ACL rules to policies
var defaultPolicyTemplate = template.Must(template.New("policy").Parse(defaultPolicyText))

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

	// Query of Rego the policy
	Query string

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
		Query:       p.Query,
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

// UpdateQueryFromRules marshals policy rules to Rego string and set it to Query
func (p *Policy) UpdateQueryFromRules() error {
	type templateRule struct {
		Group    string
		Protocol string
		Ports    string
		Action   string
	}
	type templateVars struct {
		Bidirectional bool
		All           []string
		Sources       []templateRule
		Destinations  []templateRule
	}
	queries := []string{}
	for _, r := range p.Rules {
		if !r.Enabled {
			continue
		}

		buff := new(bytes.Buffer)
		input := templateVars{
			Bidirectional: r.Bidirectional,
			All:           append(r.Destinations[:], r.Sources...),
		}

		for _, g := range r.Sources {
			input.Sources = append(input.Sources, templateRule{
				Group:    g,
				Protocol: string(r.Protocol),
				Ports:    strings.Join(r.Ports, ","),
				Action:   string(r.Action),
			})
		}

		for _, g := range r.Destinations {
			input.Destinations = append(input.Destinations, templateRule{
				Group:    g,
				Protocol: string(r.Protocol),
				Ports:    strings.Join(r.Ports, ","),
				Action:   string(r.Action),
			})
		}

		if err := defaultPolicyTemplate.Execute(buff, input); err != nil {
			return status.Errorf(status.BadRequest, "failed to update policy query: %v", err)
		}
		queries = append(queries, buff.String())
	}
	p.Query = strings.Join(queries, "\n")
	return nil
}

// FirewallRule is a rule of the firewall.
type FirewallRule struct {
	// PeerID of the peer
	PeerID string

	// PeerIP of the peer
	PeerIP string

	// Direction of the traffic
	Direction string

	// Action of the traffic
	Action string

	// Protocol of the traffic
	Protocol string

	// Port of the traffic
	Port string

	// id for internal purposes
	id string
}

// parseFromRegoResult parses the Rego result to a FirewallRule.
func (f *FirewallRule) parseFromRegoResult(value interface{}) error {
	object, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid Rego query eval result")
	}

	peerID, ok := object["ID"].(string)
	if !ok {
		return fmt.Errorf("invalid Rego query eval result peer ID type")
	}

	peerIP, ok := object["IP"].(string)
	if !ok {
		return fmt.Errorf("invalid Rego query eval result peer IP type")
	}

	direction, ok := object["Direction"].(string)
	if !ok {
		return fmt.Errorf("invalid Rego query eval result peer direction type")
	}

	action, ok := object["Action"].(string)
	if !ok {
		return fmt.Errorf("invalid Rego query eval result peer action type")
	}

	if v, ok := object["Protocol"]; ok {
		if protocol, ok := v.(string); ok {
			f.Protocol = protocol
		}
	}

	if v, ok := object["Port"]; ok {
		if port, ok := v.(string); ok {
			f.Port = port
		}
	}

	f.PeerID = peerID
	f.PeerIP = peerIP
	f.Direction = direction
	f.Action = action

	// NOTE: update this id each time when new field added
	f.id = peerID + peerIP + direction + f.Protocol + f.Port + action

	return nil
}

// queryPeersAndFwRulesByRego returns a list associated Peers and firewall rules list for this peer.
func (a *Account) queryPeersAndFwRulesByRego(
	peerID string,
	queryNumber int,
	query string,
) ([]*Peer, []*FirewallRule) {
	input := map[string]interface{}{
		"peer_id": peerID,
		"peers":   a.Peers,
		"groups":  a.Groups,
	}

	stmt, err := rego.New(
		rego.Query("data.netbird.all"),
		rego.Module("netbird", defaultPolicyModule),
		rego.Module(fmt.Sprintf("netbird-%d", queryNumber), query),
	).PrepareForEval(context.TODO())
	if err != nil {
		log.WithError(err).Error("get Rego query")
		return nil, nil
	}

	evalResult, err := stmt.Eval(
		context.TODO(),
		rego.EvalInput(input),
	)
	if err != nil {
		log.WithError(err).Error("eval Rego query")
		return nil, nil
	}

	if len(evalResult) == 0 || len(evalResult[0].Expressions) == 0 {
		log.Trace("empty Rego query eval result")
		return nil, nil
	}
	expressions, ok := evalResult[0].Expressions[0].Value.([]interface{})
	if !ok {
		return nil, nil
	}

	dst := make(map[string]struct{})
	src := make(map[string]struct{})
	peers := make([]*Peer, 0, len(expressions))
	rules := make([]*FirewallRule, 0, len(expressions))
	for _, v := range expressions {
		rule := &FirewallRule{}
		if err := rule.parseFromRegoResult(v); err != nil {
			log.WithError(err).Error("parse Rego query eval result")
			continue
		}
		rules = append(rules, rule)
		switch rule.Direction {
		case "dst":
			if _, ok := dst[rule.PeerID]; ok {
				continue
			}
			dst[rule.PeerID] = struct{}{}
		case "src":
			if _, ok := src[rule.PeerID]; ok {
				continue
			}
			src[rule.PeerID] = struct{}{}
		default:
			log.WithField("direction", rule.Direction).Error("invalid direction")
			continue
		}
	}

	added := make(map[string]struct{})
	if _, ok := src[peerID]; ok {
		for id := range dst {
			if _, ok := added[id]; !ok && id != peerID {
				added[id] = struct{}{}
			}
		}
	}
	if _, ok := dst[peerID]; ok {
		for id := range src {
			if _, ok := added[id]; !ok && id != peerID {
				added[id] = struct{}{}
			}
		}
	}

	for id := range added {
		peers = append(peers, a.Peers[id])
	}
	return peers, rules
}

// getPeersByPolicy returns all peers that given peer has access to
func (a *Account) getPeersByPolicy(peerID string) (peers []*Peer, rules []*FirewallRule) {
	exists := make(map[string]struct{})
	for _, policy := range a.Policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			srcExists := false
			srcPeers := make([]*Peer, 0, len(rule.Sources))
			for _, g := range rule.Sources {
				group, ok := a.Groups[g]
				if !ok {
					continue
				}

				for _, p := range group.Peers {
					peer := a.Peers[p]
					if peer.ID == peerID {
						srcExists = true
						continue
					}

					srcPeers = append(srcPeers, peer)
				}
			}

			dstExists := false
			dstPeers := make([]*Peer, 0, len(rule.Destinations))
			for _, g := range rule.Destinations {
				group, ok := a.Groups[g]
				if !ok {
					continue
				}

				for _, p := range group.Peers {
					peer := a.Peers[p]
					if peer.ID == peerID {
						dstExists = true
						continue
					}

					dstPeers = append(dstPeers, peer)
				}
			}

			if rule.Bidirectional {
				if dstExists {
					for _, peer := range srcPeers {
						if _, ok := exists[peer.ID]; !ok {
							peers = append(peers, peer)
						}

						for _, port := range rule.Ports {
							rules = append(rules, &FirewallRule{
								PeerID:    peer.ID,
								PeerIP:    peer.IP.String(),
								Direction: "dst",
								Action:    string(rule.Action),
								Protocol:  string(rule.Protocol),
								Port:      port,
							})
							rules = append(rules, &FirewallRule{
								PeerID:    peer.ID,
								PeerIP:    peer.IP.String(),
								Direction: "src",
								Action:    string(rule.Action),
								Protocol:  string(rule.Protocol),
								Port:      port,
							})
						}
					}
				}
			}

			if srcExists {
				for _, peer := range dstPeers {
					if _, ok := exists[peer.ID]; !ok {
						peers = append(peers, peer)
					}

					for _, port := range rule.Ports {
						rules = append(rules, &FirewallRule{
							PeerID:    peer.ID,
							PeerIP:    peer.IP.String(),
							Direction: "dst",
							Action:    string(rule.Action),
							Protocol:  string(rule.Protocol),
							Port:      port,
						})
					}
				}
			}
		}
	}

	return
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
		result[i] = &proto.FirewallRule{
			PeerID:    update[i].PeerID,
			PeerIP:    update[i].PeerIP,
			Direction: update[i].Direction,
			Action:    update[i].Action,
			Protocol:  update[i].Protocol,
			Port:      update[i].Port,
		}
	}
	return result
}
