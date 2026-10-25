package networkmap

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const peersZoneRecordTTL = 300

// PeersCustomZone builds the peers DNS zone from twin peer rows. It is the
// single source of the zone-record logic; Account.GetPeersCustomZone delegates
// here via twins.
func PeersCustomZone(ctx context.Context, accountID string, dnsDomain string, peers map[string]*nmdata.Peer, ipv6AllowedPeers map[string]struct{}) nmdata.CustomZone {
	var merr *multierror.Error

	if dnsDomain == "" {
		log.WithContext(ctx).Error("no dns domain is set, returning empty zone")
		return nmdata.CustomZone{}
	}

	customZone := nmdata.CustomZone{
		Domain:  dns.Fqdn(dnsDomain),
		Records: make([]nmdata.SimpleRecord, 0, len(peers)),
	}

	domainSuffix := "." + dnsDomain

	var sb strings.Builder
	for _, peer := range peers {
		if peer == nil {
			continue
		}
		if peer.DNSLabel == "" {
			merr = multierror.Append(merr, fmt.Errorf("peer %s has an empty DNS label", peer.ID))
			continue
		}

		sb.Grow(len(peer.DNSLabel) + len(domainSuffix))
		sb.WriteString(peer.DNSLabel)
		sb.WriteString(domainSuffix)

		fqdn := sb.String()
		customZone.Records = append(customZone.Records, nmdata.SimpleRecord{
			Name:  fqdn,
			Type:  int(dns.TypeA),
			Class: nbdns.DefaultClass,
			TTL:   peersZoneRecordTTL,
			RData: peer.IP.String(),
		})
		// Only advertise AAAA for peers that have a valid IPv6, whose client supports it,
		// and that belong to an IPv6-enabled group. Old clients don't configure v6 on their
		// WireGuard interface, so resolving their AAAA causes connections to hang.
		// Capability changes (client upgrade/downgrade, --disable-ipv6 toggle) propagate
		// to other peers via SyncPeer/LoginPeer regardless of version change, so AAAA
		// records refresh when a peer first reports the IPv6 overlay capability.
		_, peerAllowed := ipv6AllowedPeers[peer.ID]
		hasIPv6 := peer.IPv6.IsValid() && peer.SupportsIPv6() && peerAllowed
		if hasIPv6 {
			customZone.Records = append(customZone.Records, nmdata.SimpleRecord{
				Name:  fqdn,
				Type:  int(dns.TypeAAAA),
				Class: nbdns.DefaultClass,
				TTL:   peersZoneRecordTTL,
				RData: peer.IPv6.String(),
			})
		}
		sb.Reset()

		for _, extraLabel := range peer.ExtraDNSLabels {
			sb.Grow(len(extraLabel) + len(domainSuffix))
			sb.WriteString(extraLabel)
			sb.WriteString(domainSuffix)

			extraFqdn := sb.String()
			customZone.Records = append(customZone.Records, nmdata.SimpleRecord{
				Name:  extraFqdn,
				Type:  int(dns.TypeA),
				Class: nbdns.DefaultClass,
				TTL:   peersZoneRecordTTL,
				RData: peer.IP.String(),
			})
			if hasIPv6 {
				customZone.Records = append(customZone.Records, nmdata.SimpleRecord{
					Name:  extraFqdn,
					Type:  int(dns.TypeAAAA),
					Class: nbdns.DefaultClass,
					TTL:   peersZoneRecordTTL,
					RData: peer.IPv6.String(),
				})
			}
			sb.Reset()
		}

	}

	go func() {
		if merr != nil {
			log.WithContext(ctx).Errorf("error generating custom zone for account %s: %v", accountID, merr)
		}
	}()

	return customZone
}

// PeersZone is the account's peers DNS zone with its records indexed by the
// address they resolve to, so a peer's components pick their records by
// lookup instead of scanning the whole zone. A nil PeersZone is empty.
type PeersZone struct {
	zone   nmdata.CustomZone
	byAddr map[netip.Addr][]int
}

// NewPeersZone indexes the records of a peers DNS zone.
func NewPeersZone(zone nmdata.CustomZone) *PeersZone {
	byAddr := make(map[netip.Addr][]int, len(zone.Records))
	for i, record := range zone.Records {
		addr, err := netip.ParseAddr(record.RData)
		if err != nil || addr.String() != record.RData {
			continue
		}
		byAddr[addr] = append(byAddr[addr], i)
	}
	return &PeersZone{zone: zone, byAddr: byAddr}
}

// Domain returns the zone's domain.
func (z *PeersZone) Domain() string {
	if z == nil {
		return ""
	}
	return z.zone.Domain
}

// recordsOf returns, in zone order, the records resolving to an address of one
// of the peers, their IPv6 addresses only when includeIPv6 is set.
func (z *PeersZone) recordsOf(peers map[string]*nmdata.Peer, includeIPv6 bool) []nmdata.SimpleRecord {
	if z == nil || len(z.zone.Records) == 0 || len(peers) == 0 {
		return nil
	}

	var indexes []int
	for _, peer := range peers {
		if peer == nil {
			continue
		}
		indexes = append(indexes, z.byAddr[peer.IP]...)
		if includeIPv6 && peer.IPv6.IsValid() {
			indexes = append(indexes, z.byAddr[peer.IPv6]...)
		}
	}

	records := make([]nmdata.SimpleRecord, 0, len(indexes))
	for _, i := range sortedUnique(indexes) {
		records = append(records, z.zone.Records[i])
	}
	return records
}
