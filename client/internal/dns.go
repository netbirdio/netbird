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

func createPTRRecord(record nbdns.SimpleRecord, prefix netip.Prefix) (nbdns.SimpleRecord, bool) {
	ip, err := netip.ParseAddr(record.RData)
	if err != nil {
		log.Warnf("failed to parse IP address %s: %v", record.RData, err)
		return nbdns.SimpleRecord{}, false
	}

	ip = ip.Unmap()
	if !prefix.Contains(ip) {
		return nbdns.SimpleRecord{}, false
	}

	var rdnsName string
	if ip.Is4() {
		octets := strings.Split(ip.String(), ".")
		slices.Reverse(octets)
		rdnsName = dns.Fqdn(strings.Join(octets, ".") + ".in-addr.arpa")
	} else {
		// Expand to full 32 nibbles in reverse order (LSB first) per RFC 3596.
		raw := ip.As16()
		nibbles := make([]string, 32)
		for i := 0; i < 16; i++ {
			nibbles[31-i*2] = fmt.Sprintf("%x", raw[i]>>4)
			nibbles[31-i*2-1] = fmt.Sprintf("%x", raw[i]&0x0f)
		}
		rdnsName = dns.Fqdn(strings.Join(nibbles, ".") + ".ip6.arpa")
	}

	return nbdns.SimpleRecord{
		Name:  rdnsName,
		Type:  int(dns.TypePTR),
		Class: record.Class,
		TTL:   record.TTL,
		RData: dns.Fqdn(record.Name),
	}, true
}

// generateReverseZoneName creates the reverse DNS zone name for a given network.
// For IPv4 it produces an in-addr.arpa name, for IPv6 an ip6.arpa name.
func generateReverseZoneName(network netip.Prefix) (string, error) {
	networkIP := network.Masked().Addr().Unmap()
	bits := network.Bits()

	if networkIP.Is4() {
		// Round up to nearest byte.
		octetsToUse := (bits + 7) / 8

		octets := strings.Split(networkIP.String(), ".")
		if octetsToUse > len(octets) {
			return "", fmt.Errorf("invalid network mask size for reverse DNS: %d", bits)
		}

		reverseOctets := make([]string, octetsToUse)
		for i := 0; i < octetsToUse; i++ {
			reverseOctets[octetsToUse-1-i] = octets[i]
		}

		return dns.Fqdn(strings.Join(reverseOctets, ".") + ".in-addr.arpa"), nil
	}

	// IPv6: round up to nearest nibble (4-bit boundary).
	nibblesToUse := (bits + 3) / 4

	raw := networkIP.As16()
	allNibbles := make([]string, 32)
	for i := 0; i < 16; i++ {
		allNibbles[i*2] = fmt.Sprintf("%x", raw[i]>>4)
		allNibbles[i*2+1] = fmt.Sprintf("%x", raw[i]&0x0f)
	}

	// Take the first nibblesToUse nibbles (network portion), reverse them.
	used := make([]string, nibblesToUse)
	for i := 0; i < nibblesToUse; i++ {
		used[nibblesToUse-1-i] = allNibbles[i]
	}

	return dns.Fqdn(strings.Join(used, ".") + ".ip6.arpa"), nil
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

// collectPTRRecords gathers all PTR records for the given network from A and AAAA records.
func collectPTRRecords(config *nbdns.Config, prefix netip.Prefix) []nbdns.SimpleRecord {
	var records []nbdns.SimpleRecord

	for _, zone := range config.CustomZones {
		if zone.NonAuthoritative {
			continue
		}
		for _, record := range zone.Records {
			if record.Type != int(dns.TypeA) && record.Type != int(dns.TypeAAAA) {
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
