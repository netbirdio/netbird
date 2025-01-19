package internal

import (
	"net"
	"slices"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
)

func createPTRRecord(aRecord nbdns.SimpleRecord, ipNet *net.IPNet) (nbdns.SimpleRecord, bool) {
	ip := net.ParseIP(aRecord.RData)
	if ip == nil || ip.To4() == nil {
		return nbdns.SimpleRecord{}, false
	}

	if !ipNet.Contains(ip) {
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

func addReverseZone(config *nbdns.Config, ipNet *net.IPNet) {
	networkIP := ipNet.IP.Mask(ipNet.Mask)

	maskOnes, _ := ipNet.Mask.Size()
	// round up to nearest byte
	octetsToUse := (maskOnes + 7) / 8

	octets := strings.Split(networkIP.String(), ".")
	if octetsToUse > len(octets) {
		log.Warnf("invalid network mask size for reverse DNS: %d", maskOnes)
		return
	}

	reverseOctets := make([]string, octetsToUse)
	for i := 0; i < octetsToUse; i++ {
		reverseOctets[octetsToUse-1-i] = octets[i]
	}

	zoneName := dns.Fqdn(strings.Join(reverseOctets, ".") + ".in-addr.arpa")

	for _, zone := range config.CustomZones {
		if zone.Domain == zoneName {
			log.Debugf("reverse DNS zone %s already exists", zoneName)
			return
		}
	}

	var records []nbdns.SimpleRecord

	for _, zone := range config.CustomZones {
		for _, record := range zone.Records {
			if record.Type != int(dns.TypeA) {
				continue
			}

			if ptrRecord, ok := createPTRRecord(record, ipNet); ok {
				records = append(records, ptrRecord)
			}
		}
	}

	reverseZone := nbdns.CustomZone{
		Domain:  zoneName,
		Records: records,
	}

	config.CustomZones = append(config.CustomZones, reverseZone)
	log.Debugf("added reverse DNS zone: %s with %d records", zoneName, len(records))
}
