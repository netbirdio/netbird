//go:build !android

package dns

import (
	"bytes"
	"fmt"
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
func newResolvConfConfigurator(wgInterface WGIface) (hostManager, error) {
	resolvConfEntries, err := parseDefaultResolvConf()
	if err != nil {
		log.Error(err)
	}

	return &resolvconf{
		ifaceName:             wgInterface.Name(),
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
			log.Error(err)
		}
		return fmt.Errorf("unable to configure DNS for this peer using resolvconf manager without a nameserver group with all domains configured")
	}

	searchDomainList := searchDomains(config)
	searchDomainList = mergeSearchDomains(searchDomainList, r.originalSearchDomains)

	buf := prepareResolvConfContent(
		searchDomainList,
		append([]string{config.ServerIP}, r.originalNameServers...),
		r.othersConfigs)

	err = r.applyConfig(buf)
	if err != nil {
		return err
	}

	log.Infof("added %d search domains. Search list: %s", len(searchDomainList), searchDomainList)
	return nil
}

func (r *resolvconf) restoreHostDNS() error {
	cmd := exec.Command(resolvconfCommand, "-f", "-d", r.ifaceName)
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("got an error while removing resolvconf configuration for %s interface, error: %s", r.ifaceName, err)
	}
	return nil
}

func (r *resolvconf) applyConfig(content bytes.Buffer) error {
	cmd := exec.Command(resolvconfCommand, "-x", "-a", r.ifaceName)
	cmd.Stdin = &content
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("got an error while applying resolvconf configuration for %s interface, error: %s", r.ifaceName, err)
	}
	return nil
}
