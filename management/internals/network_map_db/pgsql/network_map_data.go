package networkmap_pgsql

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

func (pg *PgStore) GetNetworkMapData(ctx context.Context, accountId string) (*networkmap.NetworkMapData, error) {
	tx, err := pg.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}

	acctSettings, err := GetAccountSettingsViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get account settings: %w", err))
	}
	dnsZones, err := GetAppliedZoneCandidatesViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get applied zone candidates: %w", err))
	}
	groups, resourceToGroupIdx, err := GetGroupsViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get groups: %w", err))
	}
	nsGroups, err := GetNameServerGroupsViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get nameserver groups: %w", err))
	}
	networkResources, err := GetNetworkResourcesViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get network resources: %w", err))
	}
	routers, err := GetNetworkRoutersViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get network routers: %w", err))
	}
	network, err := GetNetworkViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get network: %w", err))
	}
	peers, proxyPeers, err := GetPeersViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get peers: %w", err))
	}
	policies, policyToDestinationResourceIdx, policyToDestinationGroupIdx, err := GetPoliciesViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get policies: %w", err))
	}
	postureChecks, postureCheckXIDToPublicID, err := GetPostureChecksViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get posture checks: %w", err))
	}
	routes, err := GetRoutesViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get routes: %w", err))
	}
	networkXIDToPublicID, err := GetNetworkXIDToPublicIdMapViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get network xid to public id map: %w", err))
	}
	allowedUserIds, groupsToUserIds, err := GetAllowedUsersViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get allowed users: %w", err))
	}
	dnsSettings, err := GetDnsSettingsViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get dns settings: %w", err))
	}
	domains, err := GetDomainsViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	services, err := GetPrivateServicesViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	proxyTargetedDomainResourceIDs, err := GetProxyTargetedDomainResourceIDsViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get proxy targeted domain resources: %w", err))
	}

	resourcePolicies := make(map[string][]*nmdata.Policy)
	for _, resource := range networkResources {
		if !resource.Enabled {
			continue
		}
		networkResourceGroups := resourceToGroupIdx[resource.ID]
		for _, policy := range policies {
			if !policy.Enabled {
				continue
			}
			if _, ok := policyToDestinationResourceIdx[policy.ID][resource.ID]; ok {
				resourcePolicies[resource.ID] = append(resourcePolicies[resource.ID], &policy) // TODO (dmitri) maybe use public id?
				continue
			}
			if groupIds, ok := policyToDestinationGroupIdx[policy.ID]; ok {
				for networkResourceGroup := range networkResourceGroups {
					if _, ok := groupIds[networkResourceGroup]; ok {
						resourcePolicies[resource.ID] = append(resourcePolicies[resource.ID], &policy)
						break
					}
				}
			}
		}
	}

	err = tx.Commit(ctx)
	if err != nil {
		// TODO log and ignore?
	}

	toret := networkmap.NetworkMapData{
		AccountSettings:                &acctSettings,
		DNSSettings:                    &dnsSettings,
		Network:                        &network,
		Peers:                          toMap(peers, func(p nmdata.Peer) string { return p.ID }),
		Groups:                         toMap(groups, func(g nmdata.Group) string { return g.ID }),
		Policies:                       toSliceOfPtrs(policies),
		ResourcePolicies:               resourcePolicies,
		Routes:                         toSliceOfPtrs(routes),
		Routers:                        routers,
		NameServerGroups:               toSliceOfPtrs(nsGroups),
		NetworkResources:               toSliceOfPtrs(networkResources),
		PostureChecks:                  toMap(postureChecks, func(pc nmdata.PostureChecks) string { return pc.ID }),
		AllowedUserIDs:                 allowedUserIds,
		GroupIDToUserIDs:               groupsToUserIds,
		NetworkXIDToPublicID:           networkXIDToPublicID, // TODO (dmitri) maybe we can switch to public ids everywhere?
		AppliedZoneCandidates:          dnsZones,
		PrivateServiceCandidates:       buildPrivateServiceCandidates(services, domains, proxyPeers),
		PostureCheckXIDToPublicID:      postureCheckXIDToPublicID,
		ProxyTargetedDomainResourceIDs: proxyTargetedDomainResourceIDs,
	}

	return &toret, nil
}

func rollbackAndReturnError(ctx context.Context, tx pgx.Tx, err error) (*networkmap.NetworkMapData, error) {
	if errr := tx.Rollback(ctx); errr != nil {
		// TODO log and ignore?
	}
	return nil, err
}

func toMap[T any](all []T, id func(t T) string) map[string]*T {
	toret := make(map[string]*T, len(all))
	for _, t := range all {
		toret[id(t)] = &t
	}
	return toret
}

func toSliceOfPtrs[T any](all []T) []*T {
	toret := make([]*T, 0, len(all))
	for _, t := range all {
		toret = append(toret, &t)
	}
	return toret
}

func serviceDomainZone(svc service, ds []domain) string {
	if domainFromSuffix(svc.Domain.String, svc.ProxyCluster.String) {
		return svc.ProxyCluster.String
	}

	var zoneName string
	for _, domain := range ds {
		if domain.TargetCluster.String != svc.ProxyCluster.String {
			continue
		}
		if domainFromSuffix(svc.Domain.String, domain.Domain.String) && len(domain.Domain.String) > len(zoneName) {
			zoneName = domain.Domain.String
		}
	}

	return zoneName
}

func domainFromSuffix(domain, suffix string) bool {
	if suffix == "" {
		return false
	}
	return domain == suffix || strings.HasSuffix(domain, "."+suffix)
}

func buildPrivateServiceCandidates(svcs []service, domains []domain, proxyPeersByCluster map[string][]*nmdata.Peer) []networkmap.PrivateServiceCandidate {
	var out []networkmap.PrivateServiceCandidate

	if len(proxyPeersByCluster) == 0 {
		return out
	}

	for _, svc := range svcs {
		if !svc.Enabled.Bool || !svc.Private.Bool {
			continue
		}
		if len(svc.AccessGroups) == 0 {
			continue
		}

		domainZone := serviceDomainZone(svc, domains)
		if domainZone == "" {
			continue
		}

		var records []nmdata.SimpleRecord
		for _, proxyPeer := range proxyPeersByCluster[svc.ProxyCluster.String] {
			if !proxyPeer.IP.IsValid() {
				continue
			}
			records = append(records, nmdata.SimpleRecord{
				Name:  dns.Fqdn(svc.Domain.String),
				Type:  int(dns.TypeA),
				Class: "IN",
				TTL:   5,
				RData: proxyPeer.IP.String(),
			})
		}
		if len(records) == 0 {
			continue
		}

		out = append(out, networkmap.PrivateServiceCandidate{
			AccessGroups: svc.AccessGroups,
			Zone: nmdata.CustomZone{
				Domain:               dns.Fqdn(domainZone),
				Records:              records,
				NonAuthoritative:     true,
				SearchDomainDisabled: true,
			},
		})
	}

	return out
}
