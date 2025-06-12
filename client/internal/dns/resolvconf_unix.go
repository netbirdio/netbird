//go:build (linux && !android) || freebsd

package dns

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const resolvconfCommand = "resolvconf"

// resolvconfType represents the type of resolvconf implementation
type resolvconfType int

func (r resolvconfType) String() string {
	switch r {
	case typeOpenresolv:
		return "openresolv"
	case typeResolvconf:
		return "resolvconf"
	default:
		return "unknown"
	}
}

const (
	typeOpenresolv resolvconfType = iota
	typeResolvconf
)

type resolvconf struct {
	ifaceName string
	implType  resolvconfType

	originalSearchDomains []string
	originalNameServers   []string
	othersConfigs         []string
}

func detectResolvconfType() (resolvconfType, error) {
	cmd := exec.Command(resolvconfCommand, "--version")
	out, err := cmd.Output()
	if err != nil {
		return typeOpenresolv, fmt.Errorf("failed to determine resolvconf type: %w", err)
	}

	if strings.Contains(string(out), "openresolv") {
		return typeOpenresolv, nil
	}
	return typeResolvconf, nil
}

func newResolvConfConfigurator(wgInterface string) (*resolvconf, error) {
	resolvConfEntries, err := parseDefaultResolvConf()
	if err != nil {
		log.Errorf("could not read original search domains from %s: %s", defaultResolvConfPath, err)
	}

	implType, err := detectResolvconfType()
	if err != nil {
		log.Warnf("failed to detect resolvconf type, defaulting to openresolv: %v", err)
		implType = typeOpenresolv
	} else {
		log.Infof("detected resolvconf type: %v", implType)
	}

	return &resolvconf{
		ifaceName:             wgInterface,
		implType:              implType,
		originalSearchDomains: resolvConfEntries.searchDomains,
		originalNameServers:   resolvConfEntries.nameServers,
		othersConfigs:         resolvConfEntries.others,
	}, nil
}

func (r *resolvconf) supportCustomPort() bool {
	return false
}

func (r *resolvconf) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
	searchDomainList := searchDomains(config)
	searchDomainList = mergeSearchDomains(searchDomainList, r.originalSearchDomains)

	buf := prepareResolvConfContent(
		searchDomainList,
		[]string{config.ServerIP},
		r.othersConfigs,
	)

	state := &ShutdownState{
		ManagerType: resolvConfManager,
		WgIface:     r.ifaceName,
	}
	if err := stateManager.UpdateState(state); err != nil {
		log.Errorf("failed to update shutdown state: %s", err)
	}

	if err := r.applyConfig(buf); err != nil {
		return fmt.Errorf("apply config: %w", err)
	}

	log.Infof("added %d search domains. Search list: %s", len(searchDomainList), searchDomainList)
	return nil
}

func (r *resolvconf) getOriginalNameservers() []string {
	return r.originalNameServers
}

func (r *resolvconf) restoreHostDNS() error {
	var cmd *exec.Cmd

	switch r.implType {
	case typeOpenresolv:
		cmd = exec.Command(resolvconfCommand, "-f", "-d", r.ifaceName)
	case typeResolvconf:
		cmd = exec.Command(resolvconfCommand, "-d", r.ifaceName)
	}

	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("removing resolvconf configuration for %s interface: %w", r.ifaceName, err)
	}

	return nil
}

func (r *resolvconf) string() string {
	return fmt.Sprintf("resolvconf (%s)", r.implType)
}

func (r *resolvconf) applyConfig(content bytes.Buffer) error {
	var cmd *exec.Cmd

	switch r.implType {
	case typeOpenresolv:
		// OpenResolv supports exclusive mode with -x
		cmd = exec.Command(resolvconfCommand, "-x", "-a", r.ifaceName)
	case typeResolvconf:
		cmd = exec.Command(resolvconfCommand, "-a", r.ifaceName)
	default:
		return fmt.Errorf("unsupported resolvconf type: %v", r.implType)
	}

	cmd.Stdin = &content
	out, err := cmd.Output()
	log.Tracef("resolvconf output: %s", out)
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
