//go:build !ios

package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const (
	netbirdDNSStateKeyFormat            = "State:/Network/Service/NetBird-%s/DNS"
	globalIPv4State                     = "State:/Network/Global/IPv4"
	primaryServiceStateKeyFormat        = "State:/Network/Service/%s/DNS"
	keySupplementalMatchDomains         = "SupplementalMatchDomains"
	keySupplementalMatchDomainsNoSearch = "SupplementalMatchDomainsNoSearch"
	keyServerAddresses                  = "ServerAddresses"
	keyServerPort                       = "ServerPort"
	arraySymbol                         = "* "
	digitSymbol                         = "# "
	scutilPath                          = "/usr/sbin/scutil"
	dscacheutilPath                     = "/usr/bin/dscacheutil"
	searchSuffix                        = "Search"
	matchSuffix                         = "Match"
	localSuffix                         = "Local"
)

type systemConfigurator struct {
	createdKeys       map[string]struct{}
	systemDNSSettings SystemDNSSettings
}

func newHostManager() (*systemConfigurator, error) {
	return &systemConfigurator{
		createdKeys: make(map[string]struct{}),
	}, nil
}

func (s *systemConfigurator) supportCustomPort() bool {
	return true
}

func (s *systemConfigurator) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
	var err error

	if err := stateManager.UpdateState(&ShutdownState{}); err != nil {
		log.Errorf("failed to update shutdown state: %s", err)
	}

	var (
		searchDomains []string
		matchDomains  []string
	)

	err = s.recordSystemDNSSettings(true)
	if err != nil {
		log.Errorf("unable to update record of System's DNS config: %s", err.Error())
	}

	if config.RouteAll {
		searchDomains = append(searchDomains, "\"\"")
		err = s.addLocalDNS()
		if err != nil {
			log.Infof("failed to enable split DNS")
		}
	}

	for _, dConf := range config.Domains {
		if dConf.Disabled {
			continue
		}
		if dConf.MatchOnly {
			matchDomains = append(matchDomains, dConf.Domain)
			continue
		}
		searchDomains = append(searchDomains, dConf.Domain)
	}

	matchKey := getKeyWithInput(netbirdDNSStateKeyFormat, matchSuffix)
	if len(matchDomains) != 0 {
		err = s.addMatchDomains(matchKey, strings.Join(matchDomains, " "), config.ServerIP, config.ServerPort)
	} else {
		log.Infof("removing match domains from the system")
		err = s.removeKeyFromSystemConfig(matchKey)
	}
	if err != nil {
		return fmt.Errorf("add match domains: %w", err)
	}

	searchKey := getKeyWithInput(netbirdDNSStateKeyFormat, searchSuffix)
	if len(searchDomains) != 0 {
		err = s.addSearchDomains(searchKey, strings.Join(searchDomains, " "), config.ServerIP, config.ServerPort)
	} else {
		log.Infof("removing search domains from the system")
		err = s.removeKeyFromSystemConfig(searchKey)
	}
	if err != nil {
		return fmt.Errorf("add search domains: %w", err)
	}

	if err := s.flushDNSCache(); err != nil {
		log.Errorf("failed to flush DNS cache: %v", err)
	}

	return nil
}

func (s *systemConfigurator) restoreHostDNS() error {
	keys := s.getRemovableKeysWithDefaults()
	for _, key := range keys {
		keyType := "search"
		if strings.Contains(key, matchSuffix) {
			keyType = "match"
		}
		log.Infof("removing %s domains from system", keyType)
		err := s.removeKeyFromSystemConfig(key)
		if err != nil {
			log.Errorf("failed to remove %s domains from system: %s", keyType, err)
		}
	}

	if err := s.flushDNSCache(); err != nil {
		log.Errorf("failed to flush DNS cache: %v", err)
	}

	return nil
}

func (s *systemConfigurator) getRemovableKeysWithDefaults() []string {
	if len(s.createdKeys) == 0 {
		// return defaults for startup calls
		return []string{getKeyWithInput(netbirdDNSStateKeyFormat, searchSuffix), getKeyWithInput(netbirdDNSStateKeyFormat, matchSuffix)}
	}

	keys := make([]string, 0, len(s.createdKeys))
	for key := range s.createdKeys {
		keys = append(keys, key)
	}
	return keys
}

func (s *systemConfigurator) removeKeyFromSystemConfig(key string) error {
	line := buildRemoveKeyOperation(key)
	_, err := runSystemConfigCommand(wrapCommand(line))
	if err != nil {
		return fmt.Errorf("remove key: %w", err)
	}

	delete(s.createdKeys, key)

	return nil
}

func (s *systemConfigurator) addLocalDNS() error {
	if s.systemDNSSettings.ServerIP == "" || len(s.systemDNSSettings.Domains) == 0 {
		err := s.recordSystemDNSSettings(true)
		log.Errorf("Unable to get system DNS configuration")
		return err
	}
	localKey := getKeyWithInput(netbirdDNSStateKeyFormat, localSuffix)
	if s.systemDNSSettings.ServerIP != "" && len(s.systemDNSSettings.Domains) != 0 {
		err := s.addSearchDomains(localKey, strings.Join(s.systemDNSSettings.Domains, " "), s.systemDNSSettings.ServerIP, s.systemDNSSettings.ServerPort)
		if err != nil {
			return fmt.Errorf("couldn't add local network DNS conf: %w", err)
		}
	} else {
		log.Info("Not enabling local DNS server")
	}

	return nil
}

func (s *systemConfigurator) recordSystemDNSSettings(force bool) error {
	if s.systemDNSSettings.ServerIP != "" && len(s.systemDNSSettings.Domains) != 0 && !force {
		return nil
	}

	systemDNSSettings, err := s.getSystemDNSSettings()
	if err != nil {
		return fmt.Errorf("couldn't get current DNS config: %w", err)
	}
	s.systemDNSSettings = systemDNSSettings

	return nil
}

func (s *systemConfigurator) getSystemDNSSettings() (SystemDNSSettings, error) {
	primaryServiceKey, _, err := s.getPrimaryService()
	if err != nil || primaryServiceKey == "" {
		return SystemDNSSettings{}, fmt.Errorf("couldn't find the primary service key: %w", err)
	}
	dnsServiceKey := getKeyWithInput(primaryServiceStateKeyFormat, primaryServiceKey)
	line := buildCommandLine("show", dnsServiceKey, "")
	stdinCommands := wrapCommand(line)

	b, err := runSystemConfigCommand(stdinCommands)
	if err != nil {
		return SystemDNSSettings{}, fmt.Errorf("sending the command: %w", err)
	}

	var dnsSettings SystemDNSSettings
	inSearchDomainsArray := false
	inServerAddressesArray := false

	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "DomainName :"):
			domainName := strings.TrimSpace(strings.Split(line, ":")[1])
			dnsSettings.Domains = append(dnsSettings.Domains, domainName)
		case line == "SearchDomains : <array> {":
			inSearchDomainsArray = true
			continue
		case line == "ServerAddresses : <array> {":
			inServerAddressesArray = true
			continue
		case line == "}":
			inSearchDomainsArray = false
			inServerAddressesArray = false
		}

		if inSearchDomainsArray {
			searchDomain := strings.Split(line, " : ")[1]
			dnsSettings.Domains = append(dnsSettings.Domains, searchDomain)
		} else if inServerAddressesArray {
			address := strings.Split(line, " : ")[1]
			if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
				dnsSettings.ServerIP = address
				inServerAddressesArray = false // Stop reading after finding the first IPv4 address
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return dnsSettings, err
	}

	// default to 53 port
	dnsSettings.ServerPort = 53

	return dnsSettings, nil
}

func (s *systemConfigurator) addSearchDomains(key, domains string, ip string, port int) error {
	err := s.addDNSState(key, domains, ip, port, true)
	if err != nil {
		return fmt.Errorf("add dns state: %w", err)
	}

	log.Infof("added %d search domains to the state. Domain list: %s", len(strings.Split(domains, " ")), domains)

	s.createdKeys[key] = struct{}{}

	return nil
}

func (s *systemConfigurator) addMatchDomains(key, domains, dnsServer string, port int) error {
	err := s.addDNSState(key, domains, dnsServer, port, false)
	if err != nil {
		return fmt.Errorf("add dns state: %w", err)
	}

	log.Infof("added %d match domains to the state. Domain list: %s", len(strings.Split(domains, " ")), domains)

	s.createdKeys[key] = struct{}{}

	return nil
}

func (s *systemConfigurator) addDNSState(state, domains, dnsServer string, port int, enableSearch bool) error {
	noSearch := "1"
	if enableSearch {
		noSearch = "0"
	}
	lines := buildAddCommandLine(keySupplementalMatchDomains, arraySymbol+domains)
	lines += buildAddCommandLine(keySupplementalMatchDomainsNoSearch, digitSymbol+noSearch)
	lines += buildAddCommandLine(keyServerAddresses, arraySymbol+dnsServer)
	lines += buildAddCommandLine(keyServerPort, digitSymbol+strconv.Itoa(port))

	addDomainCommand := buildCreateStateWithOperation(state, lines)
	stdinCommands := wrapCommand(addDomainCommand)

	_, err := runSystemConfigCommand(stdinCommands)
	if err != nil {
		return fmt.Errorf("applying state for domains %s, error: %w", domains, err)
	}
	return nil
}

func (s *systemConfigurator) getPrimaryService() (string, string, error) {
	line := buildCommandLine("show", globalIPv4State, "")
	stdinCommands := wrapCommand(line)

	b, err := runSystemConfigCommand(stdinCommands)
	if err != nil {
		return "", "", fmt.Errorf("sending the command: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(b))
	primaryService := ""
	router := ""
	for scanner.Scan() {
		text := scanner.Text()
		if strings.Contains(text, "PrimaryService") {
			primaryService = strings.TrimSpace(strings.Split(text, ":")[1])
		}
		if strings.Contains(text, "Router") {
			router = strings.TrimSpace(strings.Split(text, ":")[1])
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return primaryService, router, fmt.Errorf("scan: %w", err)
	}

	return primaryService, router, nil
}

func (s *systemConfigurator) flushDNSCache() error {
	cmd := exec.Command(dscacheutilPath, "-flushcache")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("flush DNS cache: %w, output: %s", err, out)
	}

	cmd = exec.Command("killall", "-HUP", "mDNSResponder")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restart mDNSResponder: %w, output: %s", err, out)
	}

	log.Info("flushed DNS cache")
	return nil
}

func (s *systemConfigurator) restoreUncleanShutdownDNS() error {
	if err := s.restoreHostDNS(); err != nil {
		return fmt.Errorf("restoring dns via scutil: %w", err)
	}
	return nil
}

func getKeyWithInput(format, key string) string {
	return fmt.Sprintf(format, key)
}

func buildAddCommandLine(key, value string) string {
	return buildCommandLine("d.add", key, value)
}

func buildCommandLine(action, key, value string) string {
	return fmt.Sprintf("%s %s %s\n", action, key, value)
}

func wrapCommand(commands string) string {
	return fmt.Sprintf("open\n%s\nquit\n", commands)
}

func buildRemoveKeyOperation(key string) string {
	return fmt.Sprintf("remove %s\n", key)
}

func buildCreateStateWithOperation(state, commands string) string {
	return buildWriteStateOperation("set", state, commands)
}

func buildWriteStateOperation(operation, state, commands string) string {
	return fmt.Sprintf("d.init\n%s %s\n%s\nset %s\n", operation, state, commands, state)
}

func runSystemConfigCommand(command string) ([]byte, error) {
	cmd := exec.Command(scutilPath)
	cmd.Stdin = strings.NewReader(command)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running system configuration command: \"%s\", error: %w", command, err)
	}
	return out, nil
}
