package controller

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// accountNetworkMap is one load of an account's network-map data with the
// account-wide values every peer's calculation shares, derived once per load.
// Every waiter of the load gets the same value, so it is read-only.
type accountNetworkMap struct {
	data             *networkmap.NetworkMapData
	peersZone        *networkmap.PeersZone
	dnsDomain        string
	dnsForwarderPort int64
}

// peerSelection names the peers a network-map data load has to serve; all
// selects every peer of the account.
type peerSelection struct {
	all     bool
	peerIDs map[string]struct{}
}

func allPeers() peerSelection {
	return peerSelection{all: true}
}

func selectedPeers(peerIDs ...string) peerSelection {
	set := make(map[string]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		set[id] = struct{}{}
	}
	return peerSelection{peerIDs: set}
}

// mergePeerSelections widens batched to cover request as well.
func mergePeerSelections(batched, request peerSelection) peerSelection {
	if batched.all || request.all {
		return allPeers()
	}
	for id := range request.peerIDs {
		batched.peerIDs[id] = struct{}{}
	}
	return batched
}

// getNetworkMapData returns the account's network-map data loaded for at least
// the selected peers, or nil when the dedicated store is not in use or the
// load failed, in which case callers fall back to the account path.
func (c *Controller) getNetworkMapData(ctx context.Context, accountID string, selection peerSelection) *accountNetworkMap {
	if c.nmdataBuffer == nil {
		return nil
	}

	data, err := c.nmdataBuffer.Get(ctx, accountID, selection)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get network map data for account %s, falling back to account-based computation: %v", accountID, err)
		return nil
	}

	return data
}

// fetchNetworkMapData reads the twin once per buffer window. Its result is
// shared by every waiter of that window, so the mutating steps run here, before
// it is handed out: the twin the callers see is read-only. Injected proxy
// policies carry no posture checks, so precomputing after the injection yields
// the same validation as precomputing before it.
//
// Unless every peer is selected, only the peers the selected peers' components
// can hold are read, as worked out by PeerClosure on the data read without peer
// rows. A closure covering half of the account's largest group or more reads
// every peer instead. The users are only read when a rule can ship them.
func (c *Controller) fetchNetworkMapData(ctx context.Context, accountID string, selection peerSelection) (*accountNetworkMap, error) {
	servicesCh := make(chan []*nmdata.Service, 1)
	go func() { servicesCh <- c.proxyServicesFromRepo(ctx, accountID) }()
	services := sync.OnceValue(func() []*nmdata.Service { return <-servicesCh })

	var targets []string
	var selectPeers func(nmd *networkmap.NetworkMapData) (networkmapdb.PeerSelection, error)
	if !selection.all {
		targets = maps.Keys(selection.peerIDs)
		selectPeers = func(nmd *networkmap.NetworkMapData) (networkmapdb.PeerSelection, error) {
			nmd.Services = services()
			load := networkmapdb.PeerSelection{SkipUsers: !nmd.RequiresUsers(targets...)}
			closure, ok := nmd.PeerClosure(targets, closureLimit(nmd))
			if !ok {
				load.AllPeers = true
				return load, nil
			}
			load.PeerIDs = maps.Keys(closure)
			return load, nil
		}
	}

	nmData, err := c.nmdataStore.GetNetworkMapData(ctx, accountID, targets, selectPeers)
	if err != nil {
		return nil, err
	}

	nmData.Services = services()
	nmData.BuildPrivateServiceCandidates()
	nmData.InjectProxyPolicies()
	nmData.PrecomputePostureValidation()

	dnsDomain := c.getDNSDomainFromData(nmData.AccountSettings)
	return &accountNetworkMap{
		data:             nmData,
		peersZone:        networkmap.NewPeersZone(networkmap.PeersCustomZone(ctx, accountID, dnsDomain, nmData.Peers, IPv6AllowedPeersFromData(nmData))),
		dnsDomain:        dnsDomain,
		dnsForwarderPort: computeForwarderPortFromVersions(nmData.PeerVersions, network_map.DnsForwarderPortMinVersion),
	}, nil
}

// closureLimit is the closure size from which reading every peer is cheaper
// than reading the closure: half of the account's largest group, which is
// "All" and so holds every peer.
func closureLimit(nmd *networkmap.NetworkMapData) int {
	largest := 0
	for _, g := range nmd.Groups {
		if g != nil {
			largest = max(largest, len(g.Peers))
		}
	}
	return max(largest/2, 1)
}
