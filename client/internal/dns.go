package internal

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
)

func createPTRRecord(aRecord nbdns.SimpleRecord, prefix netip.Prefix) (nbdns.SimpleRecord, bool) {
	ip, err := netip.ParseAddr(aRecord.RData)
	if err != nil {
		log.Warnf("failed to parse IP address %s: %v", aRecord.RData, err)
		return nbdns.SimpleRecord{}, false
	}

	if !prefix.Contains(ip) {
		return nbdns.SimpleRecord{}, false
	}

	ipOctets := strings.Split(ip.String(), ".")
	slices.Reverse(ipOctets)
	rdnsName := dns.Fqdn(strings.Join(ipOctets, ".") + ".in-addr.arpa")

	return nbdns.SimpleRecord{
		Name:  rdnsName,
		Type:  int(dns.TypePTR),
		Class: aRecord.Class,
		TTL:   aRecord.TTL,
		RData: dns.Fqdn(aRecord.Name),
	}, true
}

// generateReverseZoneName creates the reverse DNS zone name for a given network
func generateReverseZoneName(network netip.Prefix) (string, error) {
	networkIP := network.Masked().Addr()

	if !networkIP.Is4() {
		return "", fmt.Errorf("reverse DNS is only supported for IPv4 networks, got: %s", networkIP)
	}

	// round up to nearest byte
	octetsToUse := (network.Bits() + 7) / 8

	octets := strings.Split(networkIP.String(), ".")
	if octetsToUse > len(octets) {
		return "", fmt.Errorf("invalid network mask size for reverse DNS: %d", network.Bits())
	}

	reverseOctets := make([]string, octetsToUse)
	for i := 0; i < octetsToUse; i++ {
		reverseOctets[octetsToUse-1-i] = octets[i]
	}

	return dns.Fqdn(strings.Join(reverseOctets, ".") + ".in-addr.arpa"), nil
}

// zoneExists checks if a zone with the given name already exists in the configuration
func zoneExists(config *nbdns.Config, zoneName string) bool {
	for _, zone := range config.CustomZones {
		if zone.Domain == zoneName {
			log.Debugf("reverse DNS zone %s already exists", zoneName)
			return true
		}
	}
	return false
}

// collectPTRRecords gathers all PTR records for the given network from A records
func collectPTRRecords(config *nbdns.Config, prefix netip.Prefix) []nbdns.SimpleRecord {
	var records []nbdns.SimpleRecord

	for _, zone := range config.CustomZones {
		if zone.SkipPTRProcess {
			continue
		}
		for _, record := range zone.Records {
			if record.Type != int(dns.TypeA) {
				continue
			}

			if ptrRecord, ok := createPTRRecord(record, prefix); ok {
				records = append(records, ptrRecord)
			}
		}
	}

	return records
}

// addReverseZone adds a reverse DNS zone to the configuration for the given network
func addReverseZone(config *nbdns.Config, network netip.Prefix) {
	zoneName, err := generateReverseZoneName(network)
	if err != nil {
		log.Warn(err)
		return
	}

	if zoneExists(config, zoneName) {
		log.Debugf("reverse DNS zone %s already exists", zoneName)
		return
	}

	records := collectPTRRecords(config, network)

	reverseZone := nbdns.CustomZone{
		Domain:               zoneName,
		Records:              records,
		SearchDomainDisabled: true,
	}

	config.CustomZones = append(config.CustomZones, reverseZone)
	log.Debugf("added reverse DNS zone: %s with %d records", zoneName, len(records))
}
