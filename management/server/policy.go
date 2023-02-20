package server

import (
	"context"
	_ "embed"

	"github.com/open-policy-agent/opa/rego"
	log "github.com/sirupsen/logrus"
)

//go:embed rego/default_policy.rego
var defaultPolicy string

// getRegoPolicy returns a initialized Rego object with default rule.
func (a *Account) getRegoPolicy(policies ...string) (rego.PreparedEvalQuery, error) {
	queries := []func(*rego.Rego){
		rego.Module("policy", defaultPolicy),
		rego.Query(`peers := [peer | peer := data.netbird.default_peers[_]]`),
	}
	for _, p := range policies {
		queries = append(queries, rego.Query(p))
	}
	return rego.New(queries...).PrepareForEval(context.TODO())
}

// getPeersByPolicy returns all peers that given peer has access to.
func (a *Account) getPeersByPolicy(peerID string) []*Peer {
	srcRules, dstRules := a.GetPeerRules(peerID)

	input := map[string]interface{}{
		"peer_id":   peerID,
		"peers":     a.Peers,
		"groups":    a.Groups,
		"src_rules": srcRules,
		"dst_rules": dstRules,
	}

	query, err := a.getRegoPolicy()
	if err != nil {
		log.WithError(err).Error("get Rego policy query")
		return nil
	}

	evalResult, err := query.Eval(context.TODO(), rego.EvalInput(input))
	if err != nil {
		log.WithError(err).Error("eval Rego policy query")
		return nil
	}

	if len(evalResult) == 0 {
		log.Error("empty Rego policy eval result")
		return nil
	}

	bindings, ok := evalResult[0].Bindings["peers"].([]interface{})
	if !ok {
		return nil
	}

	peers := make([]*Peer, 0, len(bindings))
	for _, v := range bindings {
		object, ok := v.(map[string]interface{})
		if !ok {
			log.Error("invalid Rego policy eval result")
			continue
		}

		peerID, ok := object["ID"].(string)
		if !ok {
			log.Error("invalid Rego policy peer ID type")
			continue
		}

		peers = append(peers, a.Peers[peerID])
	}

	return peers
}

type Policy struct {
	ID        string
	IP        string
	Direction string
	Port      string
}
