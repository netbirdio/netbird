package agentnetwork

import "github.com/netbirdio/netbird/management/server/affectedpeers"

// init registers the agent-network service synthesiser with the affectedpeers
// resolver. Agent-network reverse-proxy services are synthesised on demand and
// never persisted, so the resolver can't load them from the store; without them
// it can't fold the embedded proxy peer into the affected set on a client
// group/peer change, and the proxy never learns a newly authorised client until
// it reconnects. Registered here (rather than via a direct
// affectedpeers→agentnetwork import) to avoid an import cycle
// (agentnetwork → account → affectedpeers).
func init() {
	affectedpeers.SetAgentNetworkSynthesizer(SynthesizeServices)
}
