//go:build !android

package dns

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

const resolvconfCommand = "resolvconf"

type resolvconf struct {
	ifaceName string

	originalSearchDomains []string
	originalNameServers   []string
	othersConfigs         []string
}

// supported "openresolv" only
func newResolvConfConfigurator(wgInterface string) (hostManager, error) {
	resolvConfEntries, err := parseDefaultResolvConf()
	if err != nil {
		log.Errorf("could not read original search domains from %s: %s", defaultResolvConfPath, err)
	}

	return &resolvconf{
		ifaceName:             wgInterface,
		originalSearchDomains: resolvConfEntries.searchDomains,
		originalNameServers:   resolvConfEntries.nameServers,
		othersConfigs:         resolvConfEntries.others,
	}, nil
}

func (r *resolvconf) supportCustomPort() bool {
	return false
}

func (r *resolvconf) applyDNSConfig(config HostDNSConfig) error {
	var err error
	if !config.RouteAll {
		err = r.restoreHostDNS()
		if err != nil {
			log.Errorf("restore host dns: %s", err)
		}
		return fmt.Errorf("unable to configure DNS for this peer using resolvconf manager without a nameserver group with all domains configured")
	}

	searchDomainList := searchDomains(config)
	searchDomainList = mergeSearchDomains(searchDomainList, r.originalSearchDomains)

	options := prepareOptionsWithTimeout(r.othersConfigs, int(dnsFailoverTimeout.Seconds()), dnsFailoverAttempts)

	buf := prepareResolvConfContent(
		searchDomainList,
		append([]string{config.ServerIP}, r.originalNameServers...),
		options)

	// create a backup for unclean shutdown detection before the resolv.conf is changed
	if err := createUncleanShutdownIndicator(defaultResolvConfPath, resolvConfManager, config.ServerIP); err != nil {
		log.Errorf("failed to create unclean shutdown resolv.conf backup: %s", err)
	}

	err = r.applyConfig(buf)
	if err != nil {
		return fmt.Errorf("apply config: %w", err)
	}

	log.Infof("added %d search domains. Search list: %s", len(searchDomainList), searchDomainList)
	return nil
}

func (r *resolvconf) restoreHostDNS() error {
	// openresolv only, debian resolvconf doesn't support "-f"
	cmd := exec.Command(resolvconfCommand, "-f", "-d", r.ifaceName)
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("removing resolvconf configuration for %s interface, error: %w", r.ifaceName, err)
	}

	if err := removeUncleanShutdownIndicator(); err != nil {
		log.Errorf("failed to remove unclean shutdown resolv.conf backup: %s", err)
	}

	return nil
}

func (r *resolvconf) applyConfig(content bytes.Buffer) error {
	// openresolv only, debian resolvconf doesn't support "-x"
	cmd := exec.Command(resolvconfCommand, "-x", "-a", r.ifaceName)
	cmd.Stdin = &content
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("applying resolvconf configuration for %s interface, error: %w", r.ifaceName, err)
	}
	return nil
}

func (r *resolvconf) restoreUncleanShutdownDNS(*netip.Addr) error {
	if err := r.restoreHostDNS(); err != nil {
		return fmt.Errorf("restoring dns for interface %s: %w", r.ifaceName, err)
	}
	return nil
}
