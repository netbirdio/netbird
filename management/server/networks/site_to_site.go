package networks

import (
	"slices"
	"strings"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/networks/types"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
)

// buildSiteToSiteConnections groups the rules that name a network resource on both sides by the
// pair of networks they join. Policies are visited in ID order, so the first network of each
// connection is stable across calls.
func buildSiteToSiteConnections(policies []*nbtypes.Policy, resources []*resourceTypes.NetworkResource) []*types.SiteToSiteConnection {
	networkOf := make(map[string]string, len(resources))
	for _, resource := range resources {
		networkOf[resource.ID] = resource.NetworkID
	}

	sorted := slices.DeleteFunc(slices.Clone(policies), func(p *nbtypes.Policy) bool {
		return p == nil
	})
	slices.SortFunc(sorted, func(a, b *nbtypes.Policy) int {
		return strings.Compare(a.ID, b.ID)
	})

	byPair := make(map[[2]string]*types.SiteToSiteConnection)
	connections := make([]*types.SiteToSiteConnection, 0)
	for _, policy := range sorted {
		for _, rule := range policy.Rules {
			source, destination, ok := ruleNetworks(rule, networkOf)
			if !ok {
				continue
			}

			key := pairKey(source, destination)
			connection, exists := byPair[key]
			if !exists {
				connection = &types.SiteToSiteConnection{NetworkIDs: [2]string{source, destination}}
				byPair[key] = connection
				connections = append(connections, connection)
			}
			if !slices.Contains(connection.PolicyIDs, policy.ID) {
				connection.PolicyIDs = append(connection.PolicyIDs, policy.ID)
			}
			connection.Enabled = connection.Enabled || (policy.Enabled && rule.Enabled)
		}
	}

	return connections
}

// ruleNetworks returns the networks of a rule's source and destination resources when both are
// network resources in different networks.
func ruleNetworks(rule *nbtypes.PolicyRule, networkOf map[string]string) (string, string, bool) {
	if rule == nil {
		return "", "", false
	}

	source, ok := resourceNetwork(rule.SourceResource, networkOf)
	if !ok {
		return "", "", false
	}

	destination, ok := resourceNetwork(rule.DestinationResource, networkOf)
	if !ok || source == destination {
		return "", "", false
	}

	return source, destination, true
}

func resourceNetwork(resource nbtypes.Resource, networkOf map[string]string) (string, bool) {
	if resource.ID == "" || resource.Type == nbtypes.ResourceTypePeer {
		return "", false
	}

	network, ok := networkOf[resource.ID]
	return network, ok
}

func pairKey(a, b string) [2]string {
	if a < b {
		return [2]string{a, b}
	}
	return [2]string{b, a}
}
