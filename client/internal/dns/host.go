package dns

type hostManager interface {
	applyDNSSettings(domains []string, ip string, port int) error
	addSearchDomain(domain string, ip string, port int) error
	removeDomainSettings(domains []string) error
	removeDNSSettings() error
}
