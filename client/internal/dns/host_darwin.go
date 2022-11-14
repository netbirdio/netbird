package dns

import (
	"bufio"
	"bytes"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os/exec"
	"strconv"
	"strings"
)

const (
	netbirdDNSStateKeyFormat            = "State:/Network/Service/NetBird-%s/DNS"
	globalIPv4State                     = "State:/Network/Global/IPv4"
	primaryServiceSetupKeyFormat        = "Setup:/Network/Service/%s/DNS"
	keyDomainName                       = "DomainName"
	keySupplementalMatchDomains         = "SupplementalMatchDomains"
	keySupplementalMatchDomainsNoSearch = "SupplementalMatchDomainsNoSearch"
	keyServerAddresses                  = "ServerAddresses"
	ServerPort                          = "ServerPort"
	arraySymbol                         = "* "
	digitSymbol                         = "# "
	scutilPath                          = "/usr/sbin/scutil"
	searchSuffix                        = "Search"
)

type systemConfigurator struct {
	primaryServiceID string
	createdKeys      map[string]struct{}
}

func newHostManager(_, iface.WGIface) hostManager {
	return &systemConfigurator{
		createdKeys: make(map[string]struct{}),
	}
}

func (s *systemConfigurator) applyDNSSettings(domains []string, ip string, port int) error {
	var err error
	for _, domain := range domains {
		if isRootZoneDomain(domain) {
			err = s.addDNSSetupForAll(ip, port)
			if err != nil {
				log.Error(err)
			}
			continue
		}
		err = s.addDNSStateForDomain(domain, ip, port)
		if err != nil {
			log.Error(err)
		}
	}
	return nil
}

func (s *systemConfigurator) addSearchDomain(domain string, ip string, port int) error {
	key := getKeyWithInput(netbirdDNSStateKeyFormat, domain+searchSuffix)
	err := s.addDNSState(key, domain, ip, port, true)
	if err != nil {
		return err
	}

	s.createdKeys[key] = struct{}{}

	return nil
}

func (s *systemConfigurator) removeDNSSettings() error {
	lines := ""
	for key := range s.createdKeys {
		lines += buildRemoveKeyOperation(key)
	}
	if s.primaryServiceID != "" {
		lines += buildRemoveKeyOperation(getKeyWithInput(primaryServiceSetupKeyFormat, s.primaryServiceID))
	}
	_, err := runSystemConfigCommand(wrapCommand(lines))
	if err != nil {
		log.Errorf("got an error while cleaning the system configuration: %s", err)
		return err
	}

	return nil
}

func (s *systemConfigurator) removeDomainSettings(domains []string) error {
	var err error
	for _, domain := range domains {
		if isRootZoneDomain(domain) {
			if s.primaryServiceID != "" {
				err = removeKeyFromSystemConfig(getKeyWithInput(primaryServiceSetupKeyFormat, s.primaryServiceID))
				if err != nil {
					log.Errorf("unable to remove primary service configuration, got error: %s", err)
					continue
				}
				s.primaryServiceID = ""
			}
			continue
		}

		key := getKeyWithInput(netbirdDNSStateKeyFormat, domain)
		err = removeKeyFromSystemConfig(key)
		if err != nil {
			log.Errorf("unable to remove system configuration for domain %s and key %s", domain, key)
			continue
		}

		delete(s.createdKeys, key)
	}
	return nil
}

func removeKeyFromSystemConfig(key string) error {
	line := buildRemoveKeyOperation(key)
	_, err := runSystemConfigCommand(wrapCommand(line))
	if err != nil {
		return err
	}
	return nil
}

func (s *systemConfigurator) addDNSStateForDomain(domain, dnsServer string, port int) error {
	key := getKeyWithInput(netbirdDNSStateKeyFormat, domain)
	err := s.addDNSState(key, domain, dnsServer, port, false)
	if err != nil {
		return err
	}

	s.createdKeys[key] = struct{}{}

	return nil
}

func (s *systemConfigurator) addDNSState(state, domain, dnsServer string, port int, enableSearch bool) error {
	noSearch := "1"
	if enableSearch {
		noSearch = "0"
	}
	lines := buildAddCommandLine(keyDomainName, domain)
	lines += buildAddCommandLine(keySupplementalMatchDomains, arraySymbol+domain)
	lines += buildAddCommandLine(keySupplementalMatchDomainsNoSearch, digitSymbol+noSearch)
	lines += buildAddCommandLine(keyServerAddresses, arraySymbol+dnsServer)
	lines += buildAddCommandLine(ServerPort, digitSymbol+strconv.Itoa(port))

	addDomainCommand := buildCreateStateWithOperation(state, lines)
	stdinCommands := wrapCommand(addDomainCommand)

	_, err := runSystemConfigCommand(stdinCommands)
	if err != nil {
		return fmt.Errorf("got error while applying dns state for domain %s, error: %s", domain, err)
	}
	return nil
}

func (s *systemConfigurator) addDNSSetupForAll(dnsServer string, port int) error {
	primaryServiceKey := s.getPrimaryService()
	if primaryServiceKey == "" {
		return fmt.Errorf("couldn't find the primary service key")
	}

	err := s.addDNSSetup(getKeyWithInput(primaryServiceSetupKeyFormat, primaryServiceKey), dnsServer, port)
	if err != nil {
		return err
	}

	s.primaryServiceID = primaryServiceKey
	return nil
}

func (s *systemConfigurator) getPrimaryService() string {
	line := buildCommandLine("show", globalIPv4State, "")
	stdinCommands := wrapCommand(line)
	b, err := runSystemConfigCommand(stdinCommands)
	if err != nil {
		log.Error("got error while sending the command: ", err)
		return ""
	}
	fmt.Printf("original command \n%s\ncommand out: %s\n,err: %v\n", stdinCommands, string(b), err)
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		text := scanner.Text()
		if strings.Contains(text, "PrimaryService") {
			return strings.TrimSpace(strings.Split(text, ":")[1])
		}
	}
	return ""
}

func (s *systemConfigurator) addDNSSetup(setupKey, dnsServer string, port int) error {
	lines := buildAddCommandLine(keySupplementalMatchDomainsNoSearch, digitSymbol+strconv.Itoa(0))
	lines += buildAddCommandLine(keyServerAddresses, arraySymbol+dnsServer)
	lines += buildAddCommandLine(ServerPort, digitSymbol+strconv.Itoa(port))
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
