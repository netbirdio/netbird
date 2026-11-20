package manager

import (
	"context"
	"net/netip"
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

	dnsDomain := ""
	if account.Settings != nil {
		dnsDomain = strings.ToLower(strings.TrimSuffix(account.Settings.DNSDomain, "."))
	}

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
		if routeMatchesHost(r, host, addr, isIP) {
			return true
		}
	}

	return false
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
