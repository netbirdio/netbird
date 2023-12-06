package dns

import (
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type iosHostManager struct {
	dnsManager IosDnsManager
	config     hostDNSConfig
}

func newHostManager(wgInterface WGIface, dnsManager IosDnsManager) (hostManager, error) {
	return &iosHostManager{
		dnsManager: dnsManager,
	}, nil
}

func (a iosHostManager) applyDNSConfig(config hostDNSConfig) error {
	var configAsString []string
	configAsString = append(configAsString, config.serverIP)
	configAsString = append(configAsString, strconv.Itoa(config.serverPort))
	configAsString = append(configAsString, strconv.FormatBool(config.routeAll))
	var domainConfigAsString []string
	for _, domain := range config.domains {
		var domainAsString []string
		domainAsString = append(domainAsString, strconv.FormatBool(domain.disabled))
		domainAsString = append(domainAsString, domain.domain)
		domainAsString = append(domainAsString, strconv.FormatBool(domain.matchOnly))
		domainConfigAsString = append(domainConfigAsString, strings.Join(domainAsString, "|"))
	}
	domainConfig := strings.Join(domainConfigAsString, ";")
	configAsString = append(configAsString, domainConfig)
	outputString := strings.Join(configAsString, ",")
	log.Debug("applyDNSConfig: " + outputString)
	a.dnsManager.ApplyDns(outputString)
	return nil
}

func (a iosHostManager) restoreHostDNS() error {
	return nil
}

func (a iosHostManager) supportCustomPort() bool {
	return false
}
