package legacynmap

import (
	"fmt"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

// SynthesizeProxyPolicies is main's Account.InjectProxyPolicies, frozen. On
// main the network-map controller called it on the account before computing,
// so a comparison that starts from the account has to apply it too. It returns
// the policies instead of appending them, so the caller can measure the legacy
// path without mutating the account the other paths share.
func SynthesizeProxyPolicies(a *Account) []*Policy {
	if len(a.Services) == 0 {
		return nil
	}

	proxyPeersByCluster := a.GetProxyPeers()
	if len(proxyPeersByCluster) == 0 {
		return nil
	}

	var out []*Policy
	for _, svc := range a.Services {
		if svc == nil || !svc.Enabled {
			continue
		}

		proxyPeers := proxyPeersByCluster[svc.ProxyCluster]
		for _, target := range svc.Targets {
			if target == nil || !target.Enabled {
				continue
			}
			port, ok := legacyTargetPort(target)
			if !ok {
				continue
			}
			path := ""
			if target.Path != nil {
				path = *target.Path
			}
			for _, proxyPeer := range proxyPeers {
				out = append(out, legacyProxyPolicy(svc, target, proxyPeer, port, path))
			}
		}

		out = append(out, legacyPrivateServicePolicies(a, svc, proxyPeers)...)
	}
	return out
}

func legacyPrivateServicePolicies(a *Account, svc *service.Service, proxyPeers []*nbpeer.Peer) []*Policy {
	if !svc.Private || len(svc.AccessGroups) == 0 || len(proxyPeers) == 0 {
		return nil
	}

	sources := make([]string, 0, len(svc.AccessGroups))
	for _, groupID := range svc.AccessGroups {
		if _, ok := a.Groups[groupID]; ok {
			sources = append(sources, groupID)
		}
	}
	if len(sources) == 0 {
		return nil
	}

	out := make([]*Policy, 0, len(proxyPeers))
	for _, proxyPeer := range proxyPeers {
		policyID := fmt.Sprintf("private-access-%s-%s", svc.ID, proxyPeer.ID)
		out = append(out, &Policy{
			ID:      policyID,
			Name:    fmt.Sprintf("Private Access to %s", svc.Name),
			Enabled: true,
			Rules: []*PolicyRule{
				{
					ID:       policyID,
					PolicyID: policyID,
					Name:     fmt.Sprintf("Allow access groups to reach %s", svc.Name),
					Enabled:  true,
					Sources:  append([]string(nil), sources...),
					DestinationResource: Resource{
						ID:   proxyPeer.ID,
						Type: ResourceTypePeer,
					},
					Bidirectional: false,
					Protocol:      PolicyRuleProtocolTCP,
					Action:        PolicyTrafficActionAccept,
					PortRanges: []RulePortRange{
						{Start: 80, End: 80},
						{Start: 443, End: 443},
					},
				},
			},
		})
	}
	return out
}

func legacyProxyPolicy(svc *service.Service, target *service.Target, proxyPeer *nbpeer.Peer, port uint16, path string) *Policy {
	policyID := fmt.Sprintf("proxy-access-%s-%s-%s", svc.ID, proxyPeer.ID, path)

	protocol := PolicyRuleProtocolTCP
	if svc.Mode == service.ModeUDP {
		protocol = sharedtypes.PolicyRuleProtocolUDP
	}

	return &Policy{
		ID:      policyID,
		Name:    fmt.Sprintf("Proxy Access to %s", svc.Name),
		Enabled: true,
		Rules: []*PolicyRule{
			{
				ID:       policyID,
				PolicyID: policyID,
				Name:     fmt.Sprintf("Allow access to %s", svc.Name),
				Enabled:  true,
				SourceResource: Resource{
					ID:   proxyPeer.ID,
					Type: ResourceTypePeer,
				},
				DestinationResource: Resource{
					ID:   target.TargetId,
					Type: sharedtypes.ResourceType(target.TargetType),
				},
				Bidirectional: false,
				Protocol:      protocol,
				Action:        PolicyTrafficActionAccept,
				PortRanges:    []RulePortRange{{Start: port, End: port}},
			},
		},
	}
}

func legacyTargetPort(target *service.Target) (uint16, bool) {
	if target.Port != 0 {
		return target.Port, true
	}

	switch target.Protocol {
	case "https", "tls":
		return 443, true
	case "http":
		return 80, true
	default:
		return 0, false
	}
}
