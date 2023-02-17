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
	queries := []func(*rego.Rego){rego.Query(defaultPolicy)}
	for _, p := range policies {
		queries = append(queries, rego.Query(p))
	}
	return rego.New(queries...).PrepareForEval(context.TODO())
}

// getPeersByPolicy returns all peers that given peer has access to.
func (a *Account) getPeersByPolicy(
	policyQuery rego.PreparedEvalQuery,
	peerID string,
	peers []*Peer,
) []*Peer {
	peersIndex := make(map[string]*Peer, len(peers))
	for _, peer := range peers {
		peersIndex[peer.ID] = peer
	}

	srcRules, dstRules := a.GetPeerRules(peerID)

	input := map[string]interface{}{
		"peer_id":   peerID,
		"peers":     peers,
		"src_rules": srcRules,
		"dst_rules": dstRules,
	}
	evalResult, err := policyQuery.Eval(context.TODO(), rego.EvalInput(input))
	if err != nil {
		log.WithError(err).Error("eval Rego policy")
		return peers
	}

	rawList, ok := evalResult[0].Bindings["peer"].([]interface{})
	if !ok {
		return peers
	}

	filteredPeers := make([]*Peer, 0, len(rawList))
	for _, item := range rawList {
		peerID, ok := item.(string)
		if !ok {
			log.Error("invalid type of peer ID from the policy eval result")
			continue
		}
		filteredPeers = append(filteredPeers, peersIndex[peerID])
	}

	return filteredPeers
}
