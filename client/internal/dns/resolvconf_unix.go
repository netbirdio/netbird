//go:build (linux && !android) || freebsd

package dns

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const resolvconfCommand = "resolvconf"

type resolvconf struct {
	ifaceName string

	originalSearchDomains []string
	originalNameServers   []string
	othersConfigs         []string
}

// supported "openresolv" only
func newResolvConfConfigurator(wgInterface string) (*resolvconf, error) {
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

func (r *resolvconf) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
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

	state := &ShutdownState{
		ManagerType: resolvConfManager,
		WgIface:     r.ifaceName,
	}
	if err := stateManager.UpdateState(state); err != nil {
		log.Errorf("failed to update shutdown state: %s", err)
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
		return fmt.Errorf("removing resolvconf configuration for %s interface: %w", r.ifaceName, err)
	}

	return nil
}

func (r *resolvconf) applyConfig(content bytes.Buffer) error {
	// openresolv only, debian resolvconf doesn't support "-x"
	cmd := exec.Command(resolvconfCommand, "-x", "-a", r.ifaceName)
	cmd.Stdin = &content
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("applying resolvconf configuration for %s interface: %w", r.ifaceName, err)
	}
	return nil
}

func (r *resolvconf) restoreUncleanShutdownDNS(*netip.Addr) error {
	if err := r.restoreHostDNS(); err != nil {
		return fmt.Errorf("restoring dns for interface %s: %w", r.ifaceName, err)
	}
	return nil
}
