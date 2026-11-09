package types

import (
	"strconv"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/version"
)

const (
	firewallRuleMinPortRangesVer = "0.48.0"
	firewallRuleMinNativeSSHVer  = "0.60.0"

	nativeSSHPortString  = "22022"
	nativeSSHPortNumber  = 22022
	defaultSSHPortString = "22"
	defaultSSHPortNumber = 22
)

type supportedFeatures struct {
	nativeSSH  bool
	portRanges bool
}

type LookupMap map[string]struct{}

// ExpandPortsAndRanges expands Ports and PortRanges of a rule into individual firewall rules.
func ExpandPortsAndRanges(base FirewallRule, rule *nmdata.PolicyRule, peer *nmdata.Peer) []*FirewallRule {
	features := peerSupportedFirewallFeatures(peer.Meta.WtVersion)

	var expanded []*FirewallRule

	for _, port := range rule.Ports {
		fr := base
		fr.Port = port
		expanded = append(expanded, &fr)
	}

	for _, portRange := range rule.PortRanges {
		if len(rule.Ports) > 0 {
			break
		}
		fr := base

		if features.portRanges {
			fr.PortRange = RulePortRange{Start: portRange.Start, End: portRange.End}
		} else {
			if portRange.Start != portRange.End {
				continue
			}
			fr.Port = strconv.FormatUint(uint64(portRange.Start), 10)
		}
		expanded = append(expanded, &fr)
	}

	if shouldCheckRulesForNativeSSH(features.nativeSSH, rule, peer) || rule.Protocol == string(PolicyRuleProtocolNetbirdSSH) {
		expanded = addNativeSSHRule(base, expanded)
	}

	return expanded
}

func addNativeSSHRule(base FirewallRule, expanded []*FirewallRule) []*FirewallRule {
	shouldAdd := false
	for _, fr := range expanded {
		if isPortInRule(nativeSSHPortString, 22022, fr) {
			return expanded
		}
		if isPortInRule(defaultSSHPortString, 22, fr) {
			shouldAdd = true
		}
	}
	if !shouldAdd {
		return expanded
	}

	fr := base
	fr.Port = nativeSSHPortString
	return append(expanded, &fr)
}

func isPortInRule(portString string, portInt uint16, rule *FirewallRule) bool {
	return rule.Port == portString || (rule.PortRange.Start <= portInt && portInt <= rule.PortRange.End)
}

func shouldCheckRulesForNativeSSH(supportsNative bool, rule *nmdata.PolicyRule, peer *nmdata.Peer) bool {
	return supportsNative && peer.SSHEnabled && peer.Meta.Flags.ServerSSHAllowed && rule.Protocol == string(PolicyRuleProtocolTCP)
}

func peerSupportedFirewallFeatures(peerVer string) supportedFeatures {
	if version.IsDevelopmentVersion(peerVer) {
		return supportedFeatures{true, true}
	}

	var features supportedFeatures

	meetMinVer, err := version.MeetsMinVersion(firewallRuleMinNativeSSHVer, peerVer)
	features.nativeSSH = err == nil && meetMinVer

	if features.nativeSSH {
		features.portRanges = true
	} else {
		meetMinVer, err = version.MeetsMinVersion(firewallRuleMinPortRangesVer, peerVer)
		features.portRanges = err == nil && meetMinVer
	}

	return features
}
