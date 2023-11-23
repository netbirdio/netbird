package network

import (
	"strconv"
	"strings"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/management_refactor/server/access_control"
	"github.com/netbirdio/netbird/management/server/management_refactor/server/peers"
)

type NetworkManager interface {
	GetPeerNetworkMap(peerID, dnsDomain string) *NetworkMap
}

type DefaultNetworkManager struct {
	accessControlManager access_control.AccessControlManager
}

func (nm *DefaultNetworkManager) GetPeerNetworkMap(peerID, dnsDomain string) *NetworkMap {
	aclPeers, firewallRules := getPeerConnectionResources(peerID)
	// exclude expired peers
	var peersToConnect []*peers.Peer
	var expiredPeers []*peers.Peer
	for _, p := range aclPeers {
		expired, _ := p.LoginExpired(a.Settings.PeerLoginExpiration)
		if a.Settings.PeerLoginExpirationEnabled && expired {
			expiredPeers = append(expiredPeers, p)
			continue
		}
		peersToConnect = append(peersToConnect, p)
	}

	routesUpdate := a.getRoutesToSync(peerID, peersToConnect)

	dnsManagementStatus := a.getPeerDNSManagementStatus(peerID)
	dnsUpdate := nbdns.Config{
		ServiceEnable: dnsManagementStatus,
	}

	if dnsManagementStatus {
		var zones []nbdns.CustomZone
		peersCustomZone := getPeersCustomZone(a, dnsDomain)
		if peersCustomZone.Domain != "" {
			zones = append(zones, peersCustomZone)
		}
		dnsUpdate.CustomZones = zones
		dnsUpdate.NameServerGroups = getPeerNSGroups(a, peerID)
	}

	return &NetworkMap{
		Peers:         peersToConnect,
		Network:       a.Network.Copy(),
		Routes:        routesUpdate,
		DNSConfig:     dnsUpdate,
		OfflinePeers:  expiredPeers,
		FirewallRules: firewallRules,
	}
}

// getPeerConnectionResources for a given peer
//
// This function returns the list of peers and firewall rules that are applicable to a given peer.
func (nm *DefaultNetworkManager) getPeerConnectionResources(peerID string) ([]*Peer, []*FirewallRule) {
	generateResources, getAccumulatedResources := a.connResourcesGenerator()
	for _, policy := range nm.accessControlManager.Policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			sourcePeers, peerInSources := getAllPeersFromGroups(a, rule.Sources, peerID)
			destinationPeers, peerInDestinations := getAllPeersFromGroups(a, rule.Destinations, peerID)

			if rule.Bidirectional {
				if peerInSources {
					generateResources(rule, destinationPeers, firewallRuleDirectionIN)
				}
				if peerInDestinations {
					generateResources(rule, sourcePeers, firewallRuleDirectionOUT)
				}
			}

			if peerInSources {
				generateResources(rule, destinationPeers, firewallRuleDirectionOUT)
			}

			if peerInDestinations {
				generateResources(rule, sourcePeers, firewallRuleDirectionIN)
			}
		}
	}

	return getAccumulatedResources()
}

// connResourcesGenerator returns generator and accumulator function which returns the result of generator calls
//
// The generator function is used to generate the list of peers and firewall rules that are applicable to a given peer.
// It safe to call the generator function multiple times for same peer and different rules no duplicates will be
// generated. The accumulator function returns the result of all the generator calls.
func (nm *DefaultNetworkManager) connResourcesGenerator() (func(*access_control.PolicyRule, []*peers.Peer, int), func() ([]*peers.Peer, []*access_control.FirewallRule)) {
	rulesExists := make(map[string]struct{})
	peersExists := make(map[string]struct{})
	rules := make([]*FirewallRule, 0)
	peers := make([]*peers.Peer, 0)

	all, err := a.GetGroupAll()
	if err != nil {
		log.Errorf("failed to get group all: %v", err)
		all = &Group{}
	}

	return func(rule *PolicyRule, groupPeers []*Peer, direction int) {
			isAll := (len(all.Peers) - 1) == len(groupPeers)
			for _, peer := range groupPeers {
				if peer == nil {
					continue
				}
				if _, ok := peersExists[peer.ID]; !ok {
					peers = append(peers, peer)
					peersExists[peer.ID] = struct{}{}
				}

				fr := FirewallRule{
					PeerIP:    peer.IP.String(),
					Direction: direction,
					Action:    string(rule.Action),
					Protocol:  string(rule.Protocol),
				}

				if isAll {
					fr.PeerIP = "0.0.0.0"
				}

				ruleID := (rule.ID + fr.PeerIP + strconv.Itoa(direction) +
					fr.Protocol + fr.Action + strings.Join(rule.Ports, ","))
				if _, ok := rulesExists[ruleID]; ok {
					continue
				}
				rulesExists[ruleID] = struct{}{}

				if len(rule.Ports) == 0 {
					rules = append(rules, &fr)
					continue
				}

				for _, port := range rule.Ports {
					pr := fr // clone rule and add set new port
					pr.Port = port
					rules = append(rules, &pr)
				}
			}
		}, func() ([]*Peer, []*FirewallRule) {
			return peers, rules
		}
}
