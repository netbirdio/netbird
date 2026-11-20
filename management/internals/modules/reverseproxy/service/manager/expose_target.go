package manager

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/status"
)

// validateExposeTargetHost checks that a caller-supplied expose target host is
// a destination the exposing peer may reach under the account's access
// policies. The proxy dials the target with its own overlay client, so without
// this check a peer could publish a destination it has no access to by reusing
// access the proxy holds for another service.
//
// The host is allowed when it is the exposing peer itself, a peer in the
// exposing peer's network map (by overlay IP or DNS label), an IP inside a
// network route in that map, or a name matching a domain route in that map.
// Anything else, including names the management server cannot tie to one of
// those destinations, is refused.
func (m *Manager) validateExposeTargetHost(ctx context.Context, accountID, peerID, host string) error {
	if host == "" {
		return nil
	}

	account, err := m.store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	peer, ok := account.Peers[peerID]
	if !ok || peer == nil {
		return status.Errorf(status.NotFound, "peer %s not found", peerID)
	}

	validatedPeers, _, err := m.accountManager.GetValidatedPeers(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get validated peers: %v", err)
		return status.Errorf(status.Internal, "get validated peers: %v", err)
	}

	netMap := account.GetPeerNetworkMapFromComponents(ctx, peerID, dns.CustomZone{}, nil, validatedPeers,
		account.GetResourcePoliciesMap(), account.GetResourceRoutersMap(), nil, account.GetActiveGroupUsers())

	dnsDomain := m.effectiveDNSDomain(account.Settings)

	if exposeTargetReachable(account, peer, netMap, dnsDomain, host) {
		return nil
	}

	return status.Errorf(status.PermissionDenied,
		"target host %s is not reachable by the exposing peer under the account's access policies", host)
}

func exposeTargetReachable(account *types.Account, peer *nbpeer.Peer, netMap *types.NetworkMap, dnsDomain, host string) bool {
	addr, err := netip.ParseAddr(host)
	isIP := err == nil
	if isIP {
		addr = addr.Unmap()
	}

	if peerMatchesHost(peer, dnsDomain, host, addr, isIP) {
		return true
	}

	if netMap == nil {
		return false
	}

	for _, mapped := range append(append([]*nmdata.Peer{}, netMap.Peers...), netMap.OfflinePeers...) {
		if mapped == nil {
			continue
		}
		if p, ok := account.Peers[mapped.ID]; ok && p != nil && peerMatchesHost(p, dnsDomain, host, addr, isIP) {
			return true
		}
	}

	for _, r := range netMap.Routes {
		if routeMatchesHost(r, host, addr, isIP) && routeAccessAllowed(account, peer, r) {
			return true
		}
	}

	return false
}

// effectiveDNSDomain mirrors the network map controller: the account's
// custom DNS domain, or the management-wide domain when none is set.
func (m *Manager) effectiveDNSDomain(settings *types.Settings) string {
	domain := ""
	if settings != nil {
		domain = settings.DNSDomain
	}
	if domain == "" && m.dnsDomain != nil {
		domain = m.dnsDomain()
	}
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

// routeAccessAllowed reports whether the routing peer's firewall admits the
// exposing peer on r. A route without access control groups is open to every
// peer it is distributed to, and the routing peer reaches its own networks. Otherwise an enabled accept rule must name the
// peer or one of its groups as a source and an access control group as a
// destination. A policy gated by posture checks is not evaluated here and
// grants nothing, and a matching drop rule denies.
func routeAccessAllowed(account *types.Account, peer *nbpeer.Peer, r *nmdata.Route) bool {
	if len(r.AccessControlGroups) == 0 || isRoutingPeer(peer, r) {
		return true
	}
	peerID := peer.ID

	allowed := false
	for _, policy := range account.Policies {
		if policy == nil || !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if !ruleCoversRouteAccess(account, peerID, rule, r.AccessControlGroups) {
				continue
			}
			if rule.Action != types.PolicyTrafficActionAccept {
				return false
			}
			if len(policy.SourcePostureChecks) == 0 {
				allowed = true
			}
		}
	}
	return allowed
}

func isRoutingPeer(peer *nbpeer.Peer, r *nmdata.Route) bool {
	return (r.PeerID != "" && r.PeerID == peer.ID) || (r.Peer != "" && (r.Peer == peer.ID || r.Peer == peer.Key))
}

func ruleCoversRouteAccess(account *types.Account, peerID string, rule *types.PolicyRule, accessGroups []string) bool {
	if rule == nil || !rule.Enabled {
		return false
	}
	if !slices.ContainsFunc(rule.Destinations, func(g string) bool { return slices.Contains(accessGroups, g) }) {
		return false
	}
	if rule.SourceResource.Type == types.ResourceTypePeer && rule.SourceResource.ID == peerID {
		return true
	}
	return slices.ContainsFunc(rule.Sources, func(groupID string) bool {
		group, ok := account.Groups[groupID]
		return ok && group != nil && slices.Contains(group.Peers, peerID)
	})
}

func routeMatchesHost(r *nmdata.Route, host string, addr netip.Addr, isIP bool) bool {
	if r == nil || !r.Enabled {
		return false
	}
	if len(r.Domains) > 0 {
		return !isIP && domainListMatches(r.Domains.ToPunycodeList(), host)
	}
	return isIP && r.Network.IsValid() && r.Network.Contains(addr)
}

func peerMatchesHost(p *nbpeer.Peer, dnsDomain, host string, addr netip.Addr, isIP bool) bool {
	if isIP {
		return (p.IP.IsValid() && p.IP.Unmap() == addr) || (p.IPv6.IsValid() && p.IPv6 == addr)
	}

	labels := []string{p.DNSLabel}
	if p.AllowExtraDNSLabels {
		labels = append(labels, p.ExtraDNSLabels...)
	}
	for _, label := range labels {
		label = strings.ToLower(label)
		if label == "" {
			continue
		}
		if host == label || (dnsDomain != "" && host == label+"."+dnsDomain) {
			return true
		}
	}
	return false
}

func domainListMatches(domains []string, host string) bool {
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if d == host {
			return true
		}
		if suffix, ok := strings.CutPrefix(d, "*."); ok && strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}
