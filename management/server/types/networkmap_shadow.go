package types

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

var (
	shadowOutputDir           = "netbird-shadow-compare"
	EnvNewNetworkMapCompacted = "NB_NETWORK_MAP_COMPACTED"
)

func (a *Account) ShadowCompareNetworkMap(
	ctx context.Context,
	peerID string,
	legacyNetworkMap *NetworkMap,
	peersCustomZone nbdns.CustomZone,
	accountZones []*zones.Zone,
	validatedPeersMap map[string]struct{},
	resourcePolicies map[string][]*Policy,
	routers map[string]map[string]*routerTypes.NetworkRouter,
	groupIDToUserIDs map[string][]string,
	metrics *telemetry.AccountManagerMetrics,
) {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.WithContext(ctx).Errorf("shadow comparison panic for peer %s: %v", peerID, r)
			}
		}()

		components := a.GetPeerNetworkMapComponents(
			ctx,
			peerID,
			peersCustomZone,
			accountZones,
			validatedPeersMap,
			resourcePolicies,
			routers,
			groupIDToUserIDs,
		)

		if components == nil {
			log.WithContext(ctx).Warnf("shadow comparison: components nil for peer %s", peerID)
			return
		}

		componentsNetworkMap := CalculateNetworkMapFromComponents(ctx, components)
		if componentsNetworkMap == nil {
			log.WithContext(ctx).Warnf("shadow comparison: components network map nil for peer %s", peerID)
			return
		}

		diff := compareNetworkMapCounts(legacyNetworkMap, componentsNetworkMap)

		legacyBytes, componentsBytes := measureSizes(legacyNetworkMap, components)
		savingsPercent := 0
		if legacyBytes > 0 {
			savingsPercent = 100 - int(float64(componentsBytes)*100/float64(legacyBytes))
		}

		if metrics != nil {
			metrics.CountShadowLegacySize(int64(legacyBytes))
			metrics.CountShadowComponentsSize(int64(componentsBytes))
			metrics.CountShadowSavingsPercent(int64(savingsPercent))
		}

		if diff.HasDifferences() {
			log.WithContext(ctx).Warnf(
				"shadow comparison MISMATCH for account %s and peer %s: %s", a.Id, peerID, diff.String())
			saveMismatchedMaps(ctx, a.Id, peerID, legacyNetworkMap, componentsNetworkMap, diff)
		} else {
			log.WithContext(ctx).Tracef("shadow comparison MATCH for account %s and peer %s", a.Id, peerID)
		}
	}()
}

func measureSizes(networkMap *NetworkMap, components *NetworkMapComponents) (legacyBytes, componentsBytes int) {
	if networkMap != nil {
		if data, err := json.Marshal(networkMap); err == nil {
			legacyBytes = len(data)
		}
	}
	if components != nil {
		if data, err := json.Marshal(components); err == nil {
			componentsBytes = len(data)
		}
	}
	return
}

type NetworkMapDiff struct {
	PeersLegacy               int
	PeersComponents           int
	OfflinePeersLegacy        int
	OfflinePeersComponents    int
	RoutesLegacy              int
	RoutesComponents          int
	FirewallRulesLegacy       int
	FirewallRulesComponents   int
	RouteFWRulesLegacy        int
	RouteFWRulesComponents    int
	ForwardingRulesLegacy     int
	ForwardingRulesComponents int
	DNSZonesLegacy            int
	DNSZonesComponents        int
	DNSNSGroupsLegacy         int
	DNSNSGroupsComponents     int
	EnableSSHLegacy           bool
	EnableSSHComponents       bool
	AuthUsersLegacy           int
	AuthUsersComponents       int
}

func (d *NetworkMapDiff) HasDifferences() bool {
	return d.PeersLegacy != d.PeersComponents ||
		d.OfflinePeersLegacy != d.OfflinePeersComponents ||
		d.RoutesLegacy != d.RoutesComponents ||
		d.FirewallRulesLegacy != d.FirewallRulesComponents ||
		d.RouteFWRulesLegacy != d.RouteFWRulesComponents ||
		d.ForwardingRulesLegacy != d.ForwardingRulesComponents ||
		d.DNSZonesLegacy != d.DNSZonesComponents ||
		d.DNSNSGroupsLegacy != d.DNSNSGroupsComponents ||
		d.EnableSSHLegacy != d.EnableSSHComponents ||
		d.AuthUsersLegacy != d.AuthUsersComponents
}

func (d *NetworkMapDiff) String() string {
	var diffs []string

	if d.PeersLegacy != d.PeersComponents {
		diffs = append(diffs, fmt.Sprintf("Peers: %d vs %d", d.PeersLegacy, d.PeersComponents))
	}
	if d.OfflinePeersLegacy != d.OfflinePeersComponents {
		diffs = append(diffs, fmt.Sprintf("OfflinePeers: %d vs %d", d.OfflinePeersLegacy, d.OfflinePeersComponents))
	}
	if d.RoutesLegacy != d.RoutesComponents {
		diffs = append(diffs, fmt.Sprintf("Routes: %d vs %d", d.RoutesLegacy, d.RoutesComponents))
	}
	if d.FirewallRulesLegacy != d.FirewallRulesComponents {
		diffs = append(diffs, fmt.Sprintf("FirewallRules: %d vs %d", d.FirewallRulesLegacy, d.FirewallRulesComponents))
	}
	if d.RouteFWRulesLegacy != d.RouteFWRulesComponents {
		diffs = append(diffs, fmt.Sprintf("RoutesFirewallRules: %d vs %d", d.RouteFWRulesLegacy, d.RouteFWRulesComponents))
	}
	if d.ForwardingRulesLegacy != d.ForwardingRulesComponents {
		diffs = append(diffs, fmt.Sprintf("ForwardingRules: %d vs %d", d.ForwardingRulesLegacy, d.ForwardingRulesComponents))
	}
	if d.DNSZonesLegacy != d.DNSZonesComponents {
		diffs = append(diffs, fmt.Sprintf("DNSZones: %d vs %d", d.DNSZonesLegacy, d.DNSZonesComponents))
	}
	if d.DNSNSGroupsLegacy != d.DNSNSGroupsComponents {
		diffs = append(diffs, fmt.Sprintf("DNSNSGroups: %d vs %d", d.DNSNSGroupsLegacy, d.DNSNSGroupsComponents))
	}
	if d.EnableSSHLegacy != d.EnableSSHComponents {
		diffs = append(diffs, fmt.Sprintf("EnableSSH: %v vs %v", d.EnableSSHLegacy, d.EnableSSHComponents))
	}
	if d.AuthUsersLegacy != d.AuthUsersComponents {
		diffs = append(diffs, fmt.Sprintf("AuthorizedUsers: %d vs %d", d.AuthUsersLegacy, d.AuthUsersComponents))
	}

	if len(diffs) == 0 {
		return "no differences"
	}

	result := ""
	for i, d := range diffs {
		if i > 0 {
			result += ", "
		}
		result += d
	}
	return result
}

func compareNetworkMapCounts(legacy, components *NetworkMap) NetworkMapDiff {
	diff := NetworkMapDiff{}

	if legacy != nil {
		diff.PeersLegacy = len(legacy.Peers)
		diff.OfflinePeersLegacy = len(legacy.OfflinePeers)
		diff.RoutesLegacy = len(legacy.Routes)
		diff.FirewallRulesLegacy = len(legacy.FirewallRules)
		diff.RouteFWRulesLegacy = len(legacy.RoutesFirewallRules)
		diff.ForwardingRulesLegacy = len(legacy.ForwardingRules)
		diff.DNSZonesLegacy = len(legacy.DNSConfig.CustomZones)
		diff.DNSNSGroupsLegacy = len(legacy.DNSConfig.NameServerGroups)
		diff.EnableSSHLegacy = legacy.EnableSSH
		diff.AuthUsersLegacy = len(legacy.AuthorizedUsers)
	}

	if components != nil {
		diff.PeersComponents = len(components.Peers)
		diff.OfflinePeersComponents = len(components.OfflinePeers)
		diff.RoutesComponents = len(components.Routes)
		diff.FirewallRulesComponents = len(components.FirewallRules)
		diff.RouteFWRulesComponents = len(components.RoutesFirewallRules)
		diff.ForwardingRulesComponents = len(components.ForwardingRules)
		diff.DNSZonesComponents = len(components.DNSConfig.CustomZones)
		diff.DNSNSGroupsComponents = len(components.DNSConfig.NameServerGroups)
		diff.EnableSSHComponents = components.EnableSSH
		diff.AuthUsersComponents = len(components.AuthorizedUsers)
	}

	return diff
}

func saveMismatchedMaps(ctx context.Context, accountID, peerID string, legacy, components *NetworkMap, diff NetworkMapDiff) {
	outputDir := filepath.Join(shadowOutputDir, accountID, peerID)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.WithContext(ctx).Errorf("failed to create shadow output dir: %v", err)
		return
	}

	timestamp := time.Now().Format("20060102-150405")

	legacyPath := filepath.Join(outputDir, timestamp+"_legacy.json")
	componentsPath := filepath.Join(outputDir, timestamp+"_components.json")
	diffPath := filepath.Join(outputDir, timestamp+"_diff.json")

	if legacyJSON, err := json.MarshalIndent(legacy, "", "  "); err == nil {
		if err := os.WriteFile(legacyPath, legacyJSON, 0644); err != nil {
			log.WithContext(ctx).Errorf("failed to write legacy map: %v", err)
		}
	}

	if componentsJSON, err := json.MarshalIndent(components, "", "  "); err == nil {
		if err := os.WriteFile(componentsPath, componentsJSON, 0644); err != nil {
			log.WithContext(ctx).Errorf("failed to write components map: %v", err)
		}
	}

	if diffJSON, err := json.MarshalIndent(diff, "", "  "); err == nil {
		if err := os.WriteFile(diffPath, diffJSON, 0644); err != nil {
			log.WithContext(ctx).Errorf("failed to write diff: %v", err)
		}
	}

	log.WithContext(ctx).Infof("shadow comparison mismatch saved to %s", outputDir)
}
