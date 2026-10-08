package networkmap

import (
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// privateServiceDNSRecordTTL is short so proxy-peer changes propagate quickly.
const privateServiceDNSRecordTTL = 5

// BuildPrivateServiceCandidates derives the per-service DNS records a private
// service publishes, from the twin's own services. It is the counterpart of
// InjectProxyPolicies: that one synthesises the ACL half of a private service,
// this one the DNS half, and both read nmd.Services so a service added to the
// twin after it was loaded — an agent-network service is synthesised in memory
// and never persisted — reaches the peer with both halves rather than one.
//
// The per-peer access-group gate and the merge by apex stay in the components
// calculation; this only precomputes what is account-wide.
func (nmd *NetworkMapData) BuildPrivateServiceCandidates() {
	if len(nmd.Services) == 0 {
		nmd.PrivateServiceCandidates = nil
		return
	}

	proxyPeersByCluster := nmd.connectedProxyPeersByCluster()
	if len(proxyPeersByCluster) == 0 {
		nmd.PrivateServiceCandidates = nil
		return
	}

	var out []PrivateServiceCandidate
	for _, svc := range nmd.Services {
		if svc == nil || !svc.Enabled || !svc.Private || len(svc.AccessGroups) == 0 || svc.Domain == "" {
			continue
		}
		proxyPeers := proxyPeersByCluster[svc.ProxyCluster]
		if len(proxyPeers) == 0 {
			continue
		}
		apex := nmd.privateServiceApex(svc)
		if apex == "" {
			continue
		}

		records := make([]nmdata.SimpleRecord, 0, len(proxyPeers))
		for _, p := range proxyPeers {
			records = append(records, nmdata.SimpleRecord{
				Name:  dns.Fqdn(svc.Domain),
				Type:  int(dns.TypeA),
				Class: "IN",
				TTL:   privateServiceDNSRecordTTL,
				RData: p.IP.String(),
			})
		}

		out = append(out, PrivateServiceCandidate{
			AccessGroups: svc.AccessGroups,
			Zone: nmdata.CustomZone{
				// NonAuthoritative keeps the zone match-only, so names without
				// an explicit record fall through to the upstream resolver
				// instead of returning NXDOMAIN for the whole apex.
				Domain:               dns.Fqdn(apex),
				Records:              records,
				NonAuthoritative:     true,
				SearchDomainDisabled: true,
			},
		})
	}

	nmd.PrivateServiceCandidates = out
}

// privateServiceApex resolves the zone a service's record hangs under: the
// cluster when the service sits directly beneath it, otherwise the longest
// registered custom domain pointing at that same cluster. A service whose
// domain matches no registered apex publishes nothing, since a zone the client
// never intercepts cannot answer the query.
func (nmd *NetworkMapData) privateServiceApex(svc *nmdata.Service) string {
	if domainUnderSuffix(svc.Domain, svc.ProxyCluster) {
		return svc.ProxyCluster
	}

	apex := ""
	for _, d := range nmd.Domains {
		if d.TargetCluster != svc.ProxyCluster {
			continue
		}
		if domainUnderSuffix(svc.Domain, d.Domain) && len(d.Domain) > len(apex) {
			apex = d.Domain
		}
	}
	return apex
}

func domainUnderSuffix(domain, suffix string) bool {
	if suffix == "" {
		return false
	}
	return domain == suffix || strings.HasSuffix(domain, "."+suffix)
}

// connectedProxyPeersByCluster groups the account's embedded proxy peers by the
// cluster they serve, keeping only connected ones.
func (nmd *NetworkMapData) connectedProxyPeersByCluster() map[string][]*nmdata.Peer {
	var out map[string][]*nmdata.Peer
	for _, peer := range nmd.Peers {
		if peer == nil || !peer.ProxyMeta.Embedded || !peer.Connected || !peer.IP.IsValid() {
			continue
		}
		if out == nil {
			out = make(map[string][]*nmdata.Peer)
		}
		out[peer.ProxyMeta.Cluster] = append(out[peer.ProxyMeta.Cluster], peer)
	}
	for _, peers := range out {
		slices.SortFunc(peers, func(a, b *nmdata.Peer) int { return strings.Compare(a.ID, b.ID) })
	}
	return out
}
