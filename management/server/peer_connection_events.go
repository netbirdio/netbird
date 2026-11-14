package server

import (
	"context"
	"net/netip"

	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

// storePeerConnectionEvent records a connection change for peer. The location_* meta
// keys match Peer.EventMeta so the dashboard renders both events the same way.
func (am *DefaultAccountManager) storePeerConnectionEvent(
	ctx context.Context, accountID string, peer *nbpeer.Peer, code activity.Activity,
	sourceIP netip.Addr,
) {
	// Snapshot strings before the asynchronous write so later peer updates cannot
	// change the historical identity or address.
	meta := map[string]any{
		"name": peer.Name,
		"ip":   peer.IP.String(),
	}
	if sourceIP.IsValid() {
		sourceIP = sourceIP.Unmap()
		meta["location_connection_ip"] = sourceIP.String()
		addConnectionLocation(meta, peer.Location, sourceIP)
	}
	am.StoreEvent(ctx, activity.SystemInitiator, peer.ID, accountID, code, meta)
}

// addConnectionLocation adds the peer's stored location only when it was resolved for
// sourceIP, so a location left over from an earlier connection is never attached.
func addConnectionLocation(meta map[string]any, location nbpeer.Location, sourceIP netip.Addr) {
	locationIP, ok := netip.AddrFromSlice(location.ConnectionIP)
	if !ok || locationIP.Unmap() != sourceIP {
		return
	}
	if location.CountryCode != "" {
		meta["location_country_code"] = location.CountryCode
	}
	if location.CityName != "" {
		meta["location_city_name"] = location.CityName
	}
}
