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
}

func newResolvConfConfigurator(wgInterface WGIface) (hostManager, error) {
	return &resolvconf{
		ifaceName: wgInterface.Name(),
	}, nil
}

func (r *resolvconf) supportCustomPort() bool {
	return false
}

func (r *resolvconf) applyDNSConfig(config hostDNSConfig) error {
	var err error
	if !config.routeAll {
		err = r.restoreHostDNS()
		if err != nil {
			log.Error(err)
		}
		return fmt.Errorf("unable to configure DNS for this peer using resolvconf manager without a nameserver group with all domains configured")
	}

	searchDomainList := searchDomains(config)

	originalSearchDomains, nameServers, others, err := originalDNSConfigs()
	if err != nil {
		log.Error(err)
	}
	searchDomainList = append(searchDomainList, originalSearchDomains...)

	buf := prepareResolvConfContent(
		searchDomainList,
		append([]string{config.serverIP}, nameServers...),
		others)

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
	cmd.Stdin = bytes.NewReader(content.Bytes())
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("got an error while applying resolvconf configuration for %s interface, error: %s", r.ifaceName, err)
	}
	return nil
}
