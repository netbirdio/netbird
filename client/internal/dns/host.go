package dns

import nbdns "github.com/netbirdio/netbird/dns"

type hostManager interface {
	applyDNSSettings(domains []string, ip string, port int) error
	addSearchDomain(domain string, ip string, port int) error
	removeDomainSettings(domains []string) error
	removeDNSSettings() error
}

func isRootZoneDomain(domain string) bool {
	return domain == nbdns.RootZone || domain == ""
}
