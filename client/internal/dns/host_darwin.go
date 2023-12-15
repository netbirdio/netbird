//go:build !ios

package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	netbirdDNSStateKeyFormat            = "State:/Network/Service/NetBird-%s/DNS"
	globalIPv4State                     = "State:/Network/Global/IPv4"
	primaryServiceSetupKeyFormat        = "Setup:/Network/Service/%s/DNS"
	keySupplementalMatchDomains         = "SupplementalMatchDomains"
	keySupplementalMatchDomainsNoSearch = "SupplementalMatchDomainsNoSearch"
	keyServerAddresses                  = "ServerAddresses"
	keyServerPort                       = "ServerPort"
	arraySymbol                         = "* "
	digitSymbol                         = "# "
	scutilPath                          = "/usr/sbin/scutil"
	searchSuffix                        = "Search"
	matchSuffix                         = "Match"
)

type systemConfigurator struct {
	// primaryServiceID primary interface in the system. AKA the interface with the default route
	primaryServiceID string
	createdKeys      map[string]struct{}
}

func newHostManager(_ WGIface) (hostManager, error) {
	return &systemConfigurator{
		createdKeys: make(map[string]struct{}),
	}, nil
}

func (s *systemConfigurator) supportCustomPort() bool {
	return true
}

func (s *systemConfigurator) applyDNSConfig(config HostDNSConfig) error {
	var err error

	if config.RouteAll {
		err = s.addDNSSetupForAll(config.ServerIP, config.ServerPort)
		if err != nil {
			return err
		}
	} else if s.primaryServiceID != "" {
		err = s.removeKeyFromSystemConfig(getKeyWithInput(primaryServiceSetupKeyFormat, s.primaryServiceID))
		if err != nil {
			return err
		}
		s.primaryServiceID = ""
		log.Infof("removed %s:%d as main DNS resolver for this peer", config.ServerIP, config.ServerPort)
	}

	var (
		searchDomains []string
		matchDomains  []string
	)

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
		return err
	}

	searchKey := getKeyWithInput(netbirdDNSStateKeyFormat, searchSuffix)
	if len(searchDomains) != 0 {
		err = s.addSearchDomains(searchKey, strings.Join(searchDomains, " "), config.ServerIP, config.ServerPort)
	} else {
		log.Infof("removing search domains from the system")
		err = s.removeKeyFromSystemConfig(searchKey)
	}
	if err != nil {
		return err
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
	if s.primaryServiceID != "" {
		lines += buildRemoveKeyOperation(getKeyWithInput(primaryServiceSetupKeyFormat, s.primaryServiceID))
		log.Infof("restoring DNS resolver configuration for system")
	}
	_, err := runSystemConfigCommand(wrapCommand(lines))
	if err != nil {
		log.Errorf("got an error while cleaning the system configuration: %s", err)
		return err
	}

	return nil
}

func (s *systemConfigurator) removeKeyFromSystemConfig(key string) error {
	line := buildRemoveKeyOperation(key)
	_, err := runSystemConfigCommand(wrapCommand(line))
	if err != nil {
		return err
	}

	delete(s.createdKeys, key)

	return nil
}

func (s *systemConfigurator) addSearchDomains(key, domains string, ip string, port int) error {
	err := s.addDNSState(key, domains, ip, port, true)
	if err != nil {
		return err
	}

	log.Infof("added %d search domains to the state. Domain list: %s", len(strings.Split(domains, " ")), domains)

	s.createdKeys[key] = struct{}{}

	return nil
}

func (s *systemConfigurator) addMatchDomains(key, domains, dnsServer string, port int) error {
	err := s.addDNSState(key, domains, dnsServer, port, false)
	if err != nil {
		return err
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
		return fmt.Errorf("got error while applying state for domains %s, error: %s", domains, err)
	}
	return nil
}

func (s *systemConfigurator) addDNSSetupForAll(dnsServer string, port int) error {
	primaryServiceKey, existingNameserver := s.getPrimaryService()
	if primaryServiceKey == "" {
		return fmt.Errorf("couldn't find the primary service key")
	}
	err := s.addDNSSetup(getKeyWithInput(primaryServiceSetupKeyFormat, primaryServiceKey), dnsServer, port, existingNameserver)
	if err != nil {
		return err
	}
	log.Infof("configured %s:%d as main DNS resolver for this peer", dnsServer, port)
	s.primaryServiceID = primaryServiceKey
	return nil
}

func (s *systemConfigurator) getPrimaryService() (string, string) {
	line := buildCommandLine("show", globalIPv4State, "")
	stdinCommands := wrapCommand(line)
	b, err := runSystemConfigCommand(stdinCommands)
	if err != nil {
		log.Error("got error while sending the command: ", err)
		return "", ""
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
	return primaryService, router
}

func (s *systemConfigurator) addDNSSetup(setupKey, dnsServer string, port int, existingDNSServer string) error {
	lines := buildAddCommandLine(keySupplementalMatchDomainsNoSearch, digitSymbol+strconv.Itoa(0))
	lines += buildAddCommandLine(keyServerAddresses, arraySymbol+dnsServer+" "+existingDNSServer)
	lines += buildAddCommandLine(keyServerPort, digitSymbol+strconv.Itoa(port))
	addDomainCommand := buildCreateStateWithOperation(setupKey, lines)
	stdinCommands := wrapCommand(addDomainCommand)
	_, err := runSystemConfigCommand(stdinCommands)
	if err != nil {
		return fmt.Errorf("got error while applying dns setup, error: %s", err)
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
		return nil, fmt.Errorf("got error while running system configuration command: \"%s\", error: %s", command, err)
	}
	return out, nil
}
