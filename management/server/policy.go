package server

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	log "github.com/sirupsen/logrus"
)

//go:embed rego/default_policy_module.rego
var defaultPolicyModule string

//go:embed rego/default_policy.rego
var defaultPolicy string

// Policy of the Rego query
type Policy struct {
	// ID of the policy
	ID string

	// Name of the Policy
	Name string

	// Description of the policy visible in the UI
	Description string

	// Disabled status of the policy
	Disabled bool

	// Query of Rego the policy
	Query string
}

// Copy returns a copy of the policy.
func (r *Policy) Copy() *Policy {
	return &Policy{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Disabled:    r.Disabled,
		Query:       r.Query,
	}
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

	// Port of the traffic
	Port string
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

	port, ok := object["Port"].(string)
	if !ok {
		return fmt.Errorf("invalid Rego query eval result peer port type")
	}

	f.PeerID = peerID
	f.PeerIP = peerIP
	f.Direction = direction
	f.Action = action
	f.Port = port

	return nil
}

// getRegoQuery returns a initialized Rego object with default rule.
func (a *Account) getRegoQuery(policies ...*Policy) (rego.PreparedEvalQuery, error) {
	queries := []func(*rego.Rego){
		rego.Query("data.netbird.all"),
		rego.Module("netbird", defaultPolicyModule),
	}
	for i, p := range policies {
		queries = append(queries, rego.Module(fmt.Sprintf("netbird-%d", i), p.Query))
	}
	return rego.New(queries...).PrepareForEval(context.TODO())
}

// getPeersByPolicy returns all peers that given peer has access to.
func (a *Account) getPeersByPolicy(peerID string) ([]*Peer, []*FirewallRule) {
	input := map[string]interface{}{
		"peer_id": peerID,
		"peers":   a.Peers,
		"groups":  a.Groups,
	}

	query, err := a.getRegoQuery(a.Policies...)
	if err != nil {
		log.WithError(err).Error("get Rego query")
		return nil, nil
	}

	evalResult, err := query.Eval(
		context.TODO(),
		rego.EvalInput(input),
	)
	if err != nil {
		log.WithError(err).Error("eval Rego query")
		return nil, nil
	}

	if len(evalResult) == 0 || len(evalResult[0].Expressions) == 0 {
		log.Error("empty Rego query eval result")
		return nil, nil
	}
	expression, ok := evalResult[0].Expressions[0].Value.([]interface{})
	if !ok {
		return nil, nil
	}

	set := make(map[string]struct{})
	peers := make([]*Peer, 0, len(expression))
	rules := make([]*FirewallRule, 0, len(expression))
	for _, v := range expression {
		rule := &FirewallRule{}
		if err := rule.parseFromRegoResult(v); err != nil {
			log.WithError(err).Error("parse Rego query eval result")
			continue
		}
		rules = append(rules, rule)
		if _, ok := set[rule.PeerID]; ok {
			continue
		}
		peers = append(peers, a.Peers[rule.PeerID])
		set[rule.PeerID] = struct{}{}
	}

	return peers, rules
}
