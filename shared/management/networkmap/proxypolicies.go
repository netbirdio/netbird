package networkmap

import (
	"fmt"
	"slices"
	"strings"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/types"
)

const (
	serviceModeUDP = "udp"

	privateServicePortHTTP  = 80
	privateServicePortHTTPS = 443
)

// InjectProxyPolicies synthesises the in-memory ACLs that carry reverse-proxy
// traffic and appends them to the twin's policies. They are never persisted,
// so no builder can load them: a proxy-access policy lets a cluster's proxy
// peers reach each enabled target of a service, and a private-access policy
// lets a private service's AccessGroups reach those proxy peers on HTTP(S).
//
// GetPeerNetworkMapComponents calls it, so every caller of the twin gets the
// same policy set no matter which builder produced it. It runs at most once
// per twin, and is safe to call again to force the synthesis early.
func (nmd *NetworkMapData) InjectProxyPolicies() {
	nmd.proxyPoliciesOnce.Do(nmd.injectProxyPolicies)
}

func (nmd *NetworkMapData) injectProxyPolicies() {
	if len(nmd.Services) == 0 {
		return
	}

	proxyPeersByCluster := nmd.proxyPeersByCluster()
	if len(proxyPeersByCluster) == 0 {
		return
	}

	for _, svc := range nmd.Services {
		if svc == nil || !svc.Enabled {
			continue
		}

		proxyPeers := proxyPeersByCluster[svc.ProxyCluster]
		for _, target := range svc.Targets {
			if target == nil || !target.Enabled {
				continue
			}
			port, ok := resolveTargetPort(target)
			if !ok {
				continue
			}
			for _, proxyPeer := range proxyPeers {
				nmd.addInjectedPolicy(proxyAccessPolicy(svc, target, proxyPeer, port))
			}
		}

		nmd.injectPrivateServicePolicies(svc, proxyPeers)
	}
}

// injectPrivateServicePolicies synthesises AccessGroups → cluster proxy peers on TCP 80/443.
func (nmd *NetworkMapData) injectPrivateServicePolicies(svc *nmdata.Service, proxyPeers []*nmdata.Peer) {
	if !svc.Private || len(svc.AccessGroups) == 0 || len(proxyPeers) == 0 {
		return
	}

	// A service's AccessGroups can name groups that no longer exist — persisted
	// services and the agent-network synthesiser both carry the ids verbatim from
	// their own state. An unresolvable source authorises nothing, so drop it here
	// rather than let the network-map assembly resolve it to a nil group.
	sources := nmd.existingGroupIDs(svc.AccessGroups)
	if len(sources) == 0 {
		return
	}

	for _, proxyPeer := range proxyPeers {
		nmd.addInjectedPolicy(privateAccessPolicy(svc, proxyPeer, sources))
	}
}

// addInjectedPolicy appends the policy to the twin's policy set, and to the
// policies of the network resource it targets — mirroring the account path,
// where the resource-policy map was built after injection.
func (nmd *NetworkMapData) addInjectedPolicy(policy *nmdata.Policy) {
	nmd.Policies = append(nmd.Policies, policy)

	resourceID := policy.Rules[0].DestinationResource.ID
	if resourceID == "" {
		return
	}
	for _, resource := range nmd.NetworkResources {
		if resource == nil || !resource.Enabled || resource.ID != resourceID {
			continue
		}
		if nmd.ResourcePolicies == nil {
			nmd.ResourcePolicies = make(map[string][]*nmdata.Policy)
		}
		nmd.ResourcePolicies[resourceID] = append(nmd.ResourcePolicies[resourceID], policy)
		return
	}
}

func proxyAccessPolicy(svc *nmdata.Service, target *nmdata.ServiceTarget, proxyPeer *nmdata.Peer, port uint16) *nmdata.Policy {
	policyID := fmt.Sprintf("proxy-access-%s-%s-%s", svc.ID, proxyPeer.ID, target.Path)

	protocol := types.PolicyRuleProtocolTCP
	if svc.Mode == serviceModeUDP {
		protocol = types.PolicyRuleProtocolUDP
	}

	return &nmdata.Policy{
		ID: policyID,
		// The envelope encoder puts public ids on the wire and degrades to an
		// empty one when a policy has none. A synthesised policy has no
		// persisted row to take a public id from, and its own id is already
		// stable and unique, so it serves as both.
		PublicID: policyID,
		Enabled:  true,
		Rules: []*nmdata.PolicyRule{
			{
				ID:                  policyID,
				PolicyID:            policyID,
				Enabled:             true,
				SourceResource:      nmdata.Resource{ID: proxyPeer.ID, Type: string(types.ResourceTypePeer)},
				DestinationResource: nmdata.Resource{ID: target.TargetID, Type: target.TargetType},
				Bidirectional:       false,
				Protocol:            string(protocol),
				Action:              string(types.PolicyTrafficActionAccept),
				PortRanges:          []nmdata.RulePortRange{{Start: port, End: port}},
			},
		},
	}
}

func privateAccessPolicy(svc *nmdata.Service, proxyPeer *nmdata.Peer, accessGroups []string) *nmdata.Policy {
	policyID := fmt.Sprintf("private-access-%s-%s", svc.ID, proxyPeer.ID)

	return &nmdata.Policy{
		ID:       policyID,
		PublicID: policyID,
		Enabled:  true,
		Rules: []*nmdata.PolicyRule{
			{
				ID:                  policyID,
				PolicyID:            policyID,
				Enabled:             true,
				Sources:             slices.Clone(accessGroups),
				DestinationResource: nmdata.Resource{ID: proxyPeer.ID, Type: string(types.ResourceTypePeer)},
				Bidirectional:       false,
				Protocol:            string(types.PolicyRuleProtocolTCP),
				Action:              string(types.PolicyTrafficActionAccept),
				PortRanges: []nmdata.RulePortRange{
					{Start: privateServicePortHTTP, End: privateServicePortHTTP},
					{Start: privateServicePortHTTPS, End: privateServicePortHTTPS},
				},
			},
		},
	}
}

func resolveTargetPort(target *nmdata.ServiceTarget) (uint16, bool) {
	if target.Port != 0 {
		return target.Port, true
	}

	switch target.Protocol {
	case "https", "tls":
		return privateServicePortHTTPS, true
	case "http":
		return privateServicePortHTTP, true
	default:
		return 0, false
	}
}

// proxyPeersByCluster groups the account's embedded proxy peers by the cluster
// they serve. Sorted by peer ID so the synthesised policy order is stable.
func (nmd *NetworkMapData) proxyPeersByCluster() map[string][]*nmdata.Peer {
	var proxyPeers map[string][]*nmdata.Peer
	for _, peer := range nmd.Peers {
		if peer == nil || !peer.ProxyMeta.Embedded {
			continue
		}
		if proxyPeers == nil {
			proxyPeers = make(map[string][]*nmdata.Peer)
		}
		proxyPeers[peer.ProxyMeta.Cluster] = append(proxyPeers[peer.ProxyMeta.Cluster], peer)
	}
	for _, peers := range proxyPeers {
		slices.SortFunc(peers, func(a, b *nmdata.Peer) int { return strings.Compare(a.ID, b.ID) })
	}
	return proxyPeers
}

// existingGroupIDs returns the subset of groupIDs that resolve to a group,
// preserving the input order.
func (nmd *NetworkMapData) existingGroupIDs(groupIDs []string) []string {
	out := make([]string, 0, len(groupIDs))
	for _, groupID := range groupIDs {
		if _, ok := nmd.Groups[groupID]; ok {
			out = append(out, groupID)
		}
	}
	return out
}
