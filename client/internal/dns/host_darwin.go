//go:build !ios

package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
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
	searchSuffix                        = "Search"
	matchSuffix                         = "Match"
	localSuffix                         = "Local"
	mgmtSuffix                          = "Mgmt"
)

// PrimaryServiceConfig from Network services
type PrimaryServiceConfig struct {
	DomainName    string
	SearchDomains []string
	ServerAddress string
}

type systemConfigurator struct {
	createdKeys          map[string]struct{}
	primaryServiceConfig PrimaryServiceConfig
}

func newHostManager() (hostManager, error) {
	return &systemConfigurator{
		createdKeys: make(map[string]struct{}),
	}, nil
}

func (s *systemConfigurator) supportCustomPort() bool {
	return true
}

func (s *systemConfigurator) applyDNSConfig(config HostDNSConfig) error {
	var err error

	// create a file for unclean shutdown detection
	if err := createUncleanShutdownIndicator(); err != nil {
		log.Errorf("failed to create unclean shutdown file: %s", err)
	}

	var (
		searchDomains []string
		matchDomains  []string
	)

	err = s.recordPrimaryServiceDNSConfig(true)
	if err != nil {
		log.Errorf("unable to update record of System's DNS config: %s", err.Error())
	}

	MgmtKey := getKeyWithInput(netbirdDNSStateKeyFormat, "Mgmt")
	err = s.addMatchDomains(MgmtKey, "netbird.yelpcorp.com netbird-canary.yelpcorp.com google.com", s.primaryServiceConfig.ServerAddress, 53)
	if err != nil {
		log.Errorf("add mgmt domains: %s", err.Error())
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

	return nil
}

func (s *systemConfigurator) restoreHostDNS() error {
	lines := ""
	for key := range s.createdKeys {
		lines += buildRemoveKeyOperation(key)
		keyType := "search"
		if strings.Contains(key, matchSuffix) {
			keyType = "match"
		}
		log.Infof("removing %s domains from system", keyType)
	}
	_, err := runSystemConfigCommand(wrapCommand(lines))
	if err != nil {
		log.Errorf("got an error while cleaning the system configuration: %s", err)
		return fmt.Errorf("clean system: %w", err)
	}

	if err := removeUncleanShutdownIndicator(); err != nil {
		log.Errorf("failed to remove unclean shutdown file: %s", err)
	}

	return nil
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
	if s.primaryServiceConfig.ServerAddress == "" || len(s.primaryServiceConfig.SearchDomains) == 0 {
		err := s.recordPrimaryServiceDNSConfig(true)
		log.Errorf("Unable to get system DNS configuration")
		return err
	}
	localKey := getKeyWithInput(netbirdDNSStateKeyFormat, localSuffix)
	if s.primaryServiceConfig.ServerAddress != "" && len(s.primaryServiceConfig.SearchDomains) != 0 {
		err := s.addSearchDomains(localKey, strings.Join(s.primaryServiceConfig.SearchDomains, " "), s.primaryServiceConfig.ServerAddress, 53)
		if err != nil {
			return fmt.Errorf("couldn't add local network DNS conf: %w", err)
		}
	} else {
		log.Info("Not enabling local DNS server")
	}

	return nil
}

func (s *systemConfigurator) recordPrimaryServiceDNSConfig(force bool) error {
	if s.primaryServiceConfig.ServerAddress != "" && len(s.primaryServiceConfig.SearchDomains) != 0 && !force {
		return nil
	}

	primaryServiceKey, _, err := s.getPrimaryService()
	if err != nil || primaryServiceKey == "" {
		return fmt.Errorf("couldn't find the primary service key: %w", err)
	}

	s.primaryServiceConfig, err = s.getPrimaryServiceConfig(primaryServiceKey)
	if err != nil {
		return fmt.Errorf("couldn't get current DNS config: %w", err)
	}

	return nil
}

func (s *systemConfigurator) getPrimaryServiceConfig(serviceKey string) (PrimaryServiceConfig, error) {
	dnsServiceKey := getKeyWithInput(primaryServiceStateKeyFormat, serviceKey)
	line := buildCommandLine("show", dnsServiceKey, "")
	stdinCommands := wrapCommand(line)

	b, err := runSystemConfigCommand(stdinCommands)
	if err != nil {
		return PrimaryServiceConfig{}, fmt.Errorf("sending the command: %w", err)
	}

	var config PrimaryServiceConfig
	inSearchDomainsArray := false
	inServerAddressesArray := false

	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "DomainName :"):
			domainName := strings.TrimSpace(strings.Split(line, ":")[1])
			config.DomainName = domainName
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
			domain := strings.Split(line, " : ")[1]
			config.SearchDomains = append(config.SearchDomains, domain)
		} else if inServerAddressesArray {
			address := strings.Split(line, " : ")[1]
			if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
				config.ServerAddress = address
				inServerAddressesArray = false // Stop reading after finding the first IPv4 address
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return config, err
	}

	if config.DomainName != "" && !slices.Contains(config.SearchDomains, config.DomainName) {
		config.SearchDomains = append(config.SearchDomains, config.DomainName)
	}

	return config, nil
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

func (s *systemConfigurator) restoreUncleanShutdownDNS(*netip.Addr) error {
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
