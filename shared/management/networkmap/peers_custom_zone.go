package networkmap

import (
	"context"
	"fmt"
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
