package dns

import (
	"bytes"
	"fmt"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"os"
)

const (
	darwinResolverContent     = "domain %s\nnameserver %s\nport %d"
	darwinSearchDomainContent = "search %s"
	fileSuffix                = "netbird"
	searchFilePrefix          = "search." + fileSuffix
	resolverPath              = "/etc/resolver"
)

func applySplitDNS(domains []string) {
	err := createResolverPath()
	if err != nil {
		log.Debugf("got an error creating resolver path: %s", err)
	}
	for _, domain := range domains {
		log.Debugf("creating file for domain: %s", domain)
		content := fmt.Sprintf(darwinResolverContent, domain, "127.0.0.1", port)
		fileName := buildPath(domain)
		writeDNSConfig(content, fileName, 0755)
	}
}

func removeSplitDNS(domainsToRemove []string) {
	for _, toRemove := range domainsToRemove {
		fileName := buildPath(toRemove)
		log.Debugf("removing file %s for domain %s", fileName, toRemove)
		_, err := os.Stat(fileName)
		if err == nil {
			err = os.RemoveAll(fileName)
			if err != nil {
				log.Debugf("got an error while removing resolver dns file %s for domain %s", fileName, toRemove)
			}
		}
	}
}

func addSearchDomain(domain string) {
	content := fmt.Sprintf(darwinSearchDomainContent, domain)
	fileName := buildPath(searchFilePrefix)
	writeDNSConfig(content, fileName, 0755)
}

func writeDNSConfig(content, fileName string, permissions os.FileMode) {
	err := createResolverPath()
	if err != nil {
		log.Debugf("got an error creating resolver path: %s", err)
	}
	log.Debugf("creating file %s", fileName)
	var buf bytes.Buffer
	buf.WriteString(content)
	err = os.WriteFile(fileName, buf.Bytes(), permissions)
	if err != nil {
		log.Debugf("got an creating resolver file %s err: %s", fileName, err)
	}
}

func buildPath(domain string) string {
	return resolverPath + "/" + dns.Fqdn(domain) + fileSuffix
}

func createResolverPath() error {
	err := os.MkdirAll(resolverPath, 0755)
	if err != nil {
		return err
	}
	return nil
}
