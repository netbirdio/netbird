//go:build !ios

package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	nberrors "github.com/netbirdio/netbird/client/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const (
	netbirdDNSStateKeyFormat            = "State:/Network/Service/NetBird-%s/DNS"
	netbirdDNSStateKeyIndexedFormat     = "State:/Network/Service/NetBird-%s-%d/DNS"
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

	// maxDomainsPerResolverEntry is the max number of domains per scutil resolver key.
	// scutil's d.add has maxArgs=101 (key + * + 99 values), so 99 is the hard cap.
	maxDomainsPerResolverEntry = 50

	// maxDomainBytesPerResolverEntry is the max total bytes of domain strings per key.
	// scutil has an undocumented ~2048 byte value buffer; we stay well under it.
	maxDomainBytesPerResolverEntry = 1500
)

type systemConfigurator struct {
	createdKeys       map[string]struct{}
	systemDNSSettings SystemDNSSettings

	mu              sync.RWMutex
	origNameservers []netip.Addr
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
	var (
		searchDomains []string
		matchDomains  []string
	)

	if err := s.recordSystemDNSSettings(true); err != nil {
		log.Errorf("unable to update record of System's DNS config: %s", err.Error())
	}

	if config.RouteAll {
		searchDomains = append(searchDomains, "\"\"")
		if err := s.addLocalDNS(); err != nil {
			log.Warnf("failed to add local DNS: %v", err)
		}
		s.updateState(stateManager)
	}

	for _, dConf := range config.Domains {
		if dConf.Disabled {
			continue
		}
		if dConf.MatchOnly {
			matchDomains = append(matchDomains, strings.TrimSuffix(dConf.Domain, "."))
			continue
		}
		searchDomains = append(searchDomains, strings.TrimSuffix(""+dConf.Domain, "."))
	}

	if err := s.removeKeysContaining(matchSuffix); err != nil {
		log.Warnf("failed to remove old match keys: %v", err)
	}
	if len(matchDomains) != 0 {
		if err := s.addBatchedDomains(matchSuffix, matchDomains, config.ServerIP, config.ServerPort, false); err != nil {
			return fmt.Errorf("add match domains: %w", err)
		}
	}
	s.updateState(stateManager)

	if err := s.removeKeysContaining(searchSuffix); err != nil {
		log.Warnf("failed to remove old search keys: %v", err)
	}
	if len(searchDomains) != 0 {
		if err := s.addBatchedDomains(searchSuffix, searchDomains, config.ServerIP, config.ServerPort, true); err != nil {
			return fmt.Errorf("add search domains: %w", err)
		}
	}
	s.updateState(stateManager)

	if err := s.flushDNSCache(); err != nil {
		log.Errorf("failed to flush DNS cache: %v", err)
	}

	return nil
}

func (s *systemConfigurator) updateState(stateManager *statemanager.Manager) {
	if err := stateManager.UpdateState(&ShutdownState{CreatedKeys: maps.Keys(s.createdKeys)}); err != nil {
		log.Errorf("failed to update shutdown state: %s", err)
	}
}

func (s *systemConfigurator) string() string {
	return "scutil"
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
		return s.discoverExistingKeys()
	}

	keys := make([]string, 0, len(s.createdKeys))
	for key := range s.createdKeys {
		keys = append(keys, key)
	}
	return keys
}

// discoverExistingKeys probes scutil for all NetBird DNS keys that may exist.
// This handles the case where createdKeys is empty (e.g., state file lost after unclean shutdown).
func (s *systemConfigurator) discoverExistingKeys() []string {
	dnsKeys, err := getSystemDNSKeys()
	if err != nil {
		log.Errorf("failed to get system DNS keys: %v", err)
		return nil
	}

	var keys []string

	for _, suffix := range []string{searchSuffix, matchSuffix, localSuffix} {
		key := getKeyWithInput(netbirdDNSStateKeyFormat, suffix)
		if strings.Contains(dnsKeys, key) {
			keys = append(keys, key)
		}
	}

	for _, suffix := range []string{searchSuffix, matchSuffix} {
		for i := 0; ; i++ {
			key := fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, suffix, i)
			if !strings.Contains(dnsKeys, key) {
				break
			}
			keys = append(keys, key)
		}
	}

	return keys
}

// getSystemDNSKeys gets all DNS keys
func getSystemDNSKeys() (string, error) {
	command := "list .*DNS\nquit\n"
	out, err := runSystemConfigCommand(command)
	if err != nil {
		return "", err
	}
	return string(out), nil
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
	if !s.systemDNSSettings.ServerIP.IsValid() || len(s.systemDNSSettings.Domains) == 0 {
		if err := s.recordSystemDNSSettings(true); err != nil {
			return fmt.Errorf("recordSystemDNSSettings(): %w", err)
		}
	}
	localKey := getKeyWithInput(netbirdDNSStateKeyFormat, localSuffix)
	if !s.systemDNSSettings.ServerIP.IsValid() || len(s.systemDNSSettings.Domains) == 0 {
		log.Info("Not enabling local DNS server")
		return nil
	}

	domainsStr := strings.Join(s.systemDNSSettings.Domains, " ")
	if err := s.addDNSState(localKey, domainsStr, s.systemDNSSettings.ServerIP, s.systemDNSSettings.ServerPort, true); err != nil {
		return fmt.Errorf("add local dns state: %w", err)
	}
	s.createdKeys[localKey] = struct{}{}

	return nil
}

func (s *systemConfigurator) recordSystemDNSSettings(force bool) error {
	if s.systemDNSSettings.ServerIP.IsValid() && len(s.systemDNSSettings.Domains) != 0 && !force {
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
	var serverAddresses []netip.Addr
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
			if ip, err := netip.ParseAddr(address); err == nil && !ip.IsUnspecified() {
				ip = ip.Unmap()
				serverAddresses = append(serverAddresses, ip)
				if !dnsSettings.ServerIP.IsValid() && ip.Is4() {
					dnsSettings.ServerIP = ip
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return dnsSettings, err
	}

	// default to 53 port
	dnsSettings.ServerPort = DefaultPort

	s.mu.Lock()
	s.origNameservers = serverAddresses
	s.mu.Unlock()

	return dnsSettings, nil
}

func (s *systemConfigurator) getOriginalNameservers() []netip.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.origNameservers)
}

// splitDomainsIntoBatches splits domains into batches respecting both element count and byte size limits.
func splitDomainsIntoBatches(domains []string) [][]string {
	if len(domains) == 0 {
		return nil
	}

	var batches [][]string
	var current []string
	currentBytes := 0

	for _, d := range domains {
		domainLen := len(d)
		newBytes := currentBytes + domainLen
		if currentBytes > 0 {
			newBytes++ // space separator
		}

		if len(current) > 0 && (len(current) >= maxDomainsPerResolverEntry || newBytes > maxDomainBytesPerResolverEntry) {
			batches = append(batches, current)
			current = nil
			currentBytes = 0
		}

		current = append(current, d)
		if currentBytes > 0 {
			currentBytes += 1 + domainLen
		} else {
			currentBytes = domainLen
		}
	}

	if len(current) > 0 {
		batches = append(batches, current)
	}

	return batches
}

// removeKeysContaining removes all created keys that contain the given substring.
func (s *systemConfigurator) removeKeysContaining(suffix string) error {
	var toRemove []string
	for key := range s.createdKeys {
		if strings.Contains(key, suffix) {
			toRemove = append(toRemove, key)
		}
	}
	var multiErr *multierror.Error
	for _, key := range toRemove {
		if err := s.removeKeyFromSystemConfig(key); err != nil {
			multiErr = multierror.Append(multiErr, fmt.Errorf("couldn't remove key %s: %w", key, err))
		}
	}
	return nberrors.FormatErrorOrNil(multiErr)
}

// addBatchedDomains splits domains into batches and creates indexed scutil keys for each batch.
func (s *systemConfigurator) addBatchedDomains(suffix string, domains []string, ip netip.Addr, port int, enableSearch bool) error {
	batches := splitDomainsIntoBatches(domains)

	for i, batch := range batches {
		key := fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, suffix, i)
		domainsStr := strings.Join(batch, " ")

		if err := s.addDNSState(key, domainsStr, ip, port, enableSearch); err != nil {
			return fmt.Errorf("add dns state for batch %d: %w", i, err)
		}

		s.createdKeys[key] = struct{}{}
	}

	log.Infof("added %d %s domains across %d resolver entries", len(domains), suffix, len(batches))

	return nil
}

func (s *systemConfigurator) addDNSState(state, domains string, dnsServer netip.Addr, port int, enableSearch bool) error {
	noSearch := "1"
	if enableSearch {
		noSearch = "0"
	}
	lines := buildAddCommandLine(keySupplementalMatchDomains, arraySymbol+domains)
	lines += buildAddCommandLine(keySupplementalMatchDomainsNoSearch, digitSymbol+noSearch)
	lines += buildAddCommandLine(keyServerAddresses, arraySymbol+dnsServer.String())
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
