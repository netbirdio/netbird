package dns

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/netbirdio/netbird/iface"
	log "github.com/sirupsen/logrus"
)

const resolvconfCommand = "resolvconf"

type resolvconf struct {
	ifaceName string
}

func newResolvConfConfigurator(wgInterface *iface.WGIface) (hostManager, error) {
	return &resolvconf{
		ifaceName: wgInterface.GetName(),
	}, nil
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

	var searchDomains string
	appendedDomains := 0
	for _, dConf := range config.domains {
		if dConf.matchOnly || dConf.disabled {
			continue
		}

		if appendedDomains >= fileMaxNumberOfSearchDomains {
			// lets log all skipped domains
			log.Infof("already appended %d domains to search list. Skipping append of %s domain", fileMaxNumberOfSearchDomains, dConf.domain)
			continue
		}

		if fileSearchLineBeginCharCount+len(searchDomains) > fileMaxLineCharsLimit {
			// lets log all skipped domains
			log.Infof("search list line is larger than %d characters. Skipping append of %s domain", fileMaxLineCharsLimit, dConf.domain)
			continue
		}

		searchDomains += " " + dConf.domain
		appendedDomains++
	}

	content := fmt.Sprintf(fileGeneratedResolvConfContentFormat, fileDefaultResolvConfBackupLocation, config.serverIP, searchDomains)

	err = r.applyConfig(content)
	if err != nil {
		return err
	}

	log.Infof("added %d search domains. Search list: %s", appendedDomains, searchDomains)
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

func (r *resolvconf) applyConfig(content string) error {
	cmd := exec.Command(resolvconfCommand, "-x", "-a", r.ifaceName)
	cmd.Stdin = strings.NewReader(content)
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("got an error while appying resolvconf configuration for %s interface, error: %s", r.ifaceName, err)
	}
	return nil
}
