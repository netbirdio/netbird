//go:build !ios

package dns

import (
	"bufio"
	"bytes"
	"context"
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
	netbirdDNSStateKeyFormat            = "State:/Network/Service/NetBird-%s-%s/DNS"
	netbirdDNSStateKeyIndexedFormat     = "State:/Network/Service/NetBird-%s-%s-%d/DNS"
	globalIPv4State                     = "State:/Network/Global/IPv4"
	primaryServiceStateKeyFormat        = "State:/Network/Service/%s/DNS"
	keySupplementalMatchDomains         = "SupplementalMatchDomains"
	keySupplementalMatchDomainsNoSearch = "SupplementalMatchDomainsNoSearch"
	keyServerAddresses                  = "ServerAddresses"
	keyServerPort                       = "ServerPort"
	arraySymbol                         = "* "
	digitSymbol                         = "# "
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

var scutilPath = "/usr/sbin/scutil"

type systemConfigurator struct {
	createdKeys       map[string]struct{}
	systemDNSSettings SystemDNSSettings
	interfaceName     string

	mu              sync.RWMutex
	origNameservers []netip.Addr
}

func newHostManager(interfaceName string) (*systemConfigurator, error) {
	if interfaceName == "" {
		return nil, fmt.Errorf("interfaceName must not be empty")
	}
	return &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: interfaceName,
	}, nil
}

func (s *systemConfigurator) supportCustomPort() bool {
	return true
}

func (s *systemConfigurator) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
	// Persist cleanup state before scutil mutations so crash recovery can find scoped keys.
	if err := s.persistShutdownState(stateManager); err != nil {
		return fmt.Errorf("persist shutdown state before applying dns config: %w", err)
	}

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
	if err := stateManager.UpdateState(&ShutdownState{
		InterfaceName: s.interfaceName,
		CreatedKeys:   maps.Keys(s.createdKeys),
	}); err != nil {
		log.Errorf("failed to update shutdown state: %s", err)
	}
}

func (s *systemConfigurator) persistShutdownState(stateManager *statemanager.Manager) error {
	if err := stateManager.UpdateState(&ShutdownState{
		InterfaceName: s.interfaceName,
		CreatedKeys:   maps.Keys(s.createdKeys),
	}); err != nil {
		return fmt.Errorf("update dns shutdown state: %w", err)
	}
	if err := stateManager.PersistState(context.Background()); err != nil {
		return fmt.Errorf("persist dns shutdown state: %w", err)
	}
	return nil
}

func (s *systemConfigurator) string() string {
	return "scutil"
}

func (s *systemConfigurator) restoreHostDNS() error {
	keys, err := s.getRemovableKeysWithDefaults()
	if err != nil {
		return fmt.Errorf("discover removable DNS keys: %w", err)
	}

	var multiErr *multierror.Error
	for _, key := range keys {
		keyType := "search"
		if strings.Contains(key, matchSuffix) {
			keyType = "match"
		}
		log.Infof("removing %s domains from system", keyType)
		if err := s.removeKeyFromSystemConfig(key); err != nil {
			multiErr = multierror.Append(multiErr, fmt.Errorf("remove %s key %s: %w", keyType, key, err))
		}
	}

	// Cache flush stays best-effort: leaving DNS cached for a few
	// seconds is preferable to falsely reporting cleanup failure.
	if err := s.flushDNSCache(); err != nil {
		log.Errorf("failed to flush DNS cache: %v", err)
	}

	return nberrors.FormatErrorOrNil(multiErr)
}

// getRemovableKeysWithDefaults unions recorded keys with interface-scoped discovery, deduplicated.
// Recovers keys omitted by partially persisted state
// (e.g. a batch key added after the last state save)
// while never probing legacy global keys during normal, current-format teardown.
func (s *systemConfigurator) getRemovableKeysWithDefaults() ([]string, error) {
	seen := make(map[string]struct{}, len(s.createdKeys))
	var keys []string
	add := func(key string) {
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}

	for key := range s.createdKeys {
		add(key)
	}
	discoveredKeys, err := s.discoverExistingKeys()
	if err != nil {
		return nil, fmt.Errorf("discover existing DNS keys: %w", err)
	}
	for _, key := range discoveredKeys {
		add(key)
	}
	return keys, nil
}

// discoverExistingKeys probes scutil for interface-scoped NetBird DNS keys only.
// Handles the case where createdKeys omits a key that was created on the system
// (e.g., state file saved before the last batch was written).
// Returns no keys and no error if the configurator has no interface name,
// since scoped discovery is meaningless without one.
func (s *systemConfigurator) discoverExistingKeys() ([]string, error) {
	if s.interfaceName == "" {
		return nil, nil
	}

	dnsKeys, err := getSystemDNSKeys()
	if err != nil {
		return nil, fmt.Errorf("get system DNS keys: %w", err)
	}

	return scopedKeysFromList(dnsKeys, s.interfaceName), nil
}

// scopedKeysFromList extracts interface-scoped NetBird DNS keys from scutil list output.
func scopedKeysFromList(dnsKeys, iface string) []string {
	var keys []string

	for _, suffix := range []string{searchSuffix, matchSuffix, localSuffix} {
		key := getKeyWithInput(netbirdDNSStateKeyFormat, iface, suffix)
		if strings.Contains(dnsKeys, key) {
			keys = append(keys, key)
		}
	}

	for _, suffix := range []string{searchSuffix, matchSuffix} {
		keys = append(keys, indexedScopedKeysFromList(dnsKeys, iface, suffix)...)
	}

	return keys
}

// indexedScopedKeysFromList scans the actual key list so sparse indices are recovered.
func indexedScopedKeysFromList(dnsKeys, iface, suffix string) []string {
	prefix := fmt.Sprintf("State:/Network/Service/NetBird-%s-%s-", iface, suffix)
	const dnsKeySuffix = "/DNS"

	seen := make(map[int]struct{})
	var indices []int

	scanner := bufio.NewScanner(strings.NewReader(dnsKeys))
	for scanner.Scan() {
		line := scanner.Text()
		start := strings.Index(line, prefix)
		if start < 0 {
			continue
		}
		rest := line[start+len(prefix):]
		end := strings.Index(rest, dnsKeySuffix)
		if end < 0 {
			continue
		}
		idx, err := strconv.Atoi(rest[:end])
		if err != nil || idx < 0 {
			continue
		}
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		indices = append(indices, idx)
	}

	slices.Sort(indices)

	keys := make([]string, 0, len(indices))
	for _, idx := range indices {
		keys = append(keys, fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, iface, suffix, idx))
	}
	return keys
}

// discoverLegacyDNSKeys probes scutil for non-interface-scoped NetBird DNS keys written by older versions
// (before per-interface scoping existed).
// It never returns interface-scoped keys.
// Callers use this only for legacy state without an interface name;
// normal current-format teardown must not call this,
// since the discovered keys may belong to a concurrently running old-version instance.
func discoverLegacyDNSKeys() ([]string, error) {
	dnsKeys, err := getSystemDNSKeys()
	if err != nil {
		return nil, fmt.Errorf("get system DNS keys: %w", err)
	}

	var keys []string
	for _, suffix := range []string{searchSuffix, matchSuffix, localSuffix} {
		legacyKey := fmt.Sprintf("State:/Network/Service/NetBird-%s/DNS", suffix)
		if strings.Contains(dnsKeys, legacyKey) {
			log.Infof("discovered legacy DNS key (no interface scope): %s", legacyKey)
			keys = append(keys, legacyKey)
		}
	}
	for _, suffix := range []string{searchSuffix, matchSuffix} {
		for i := 0; ; i++ {
			legacyKey := fmt.Sprintf("State:/Network/Service/NetBird-%s-%d/DNS", suffix, i)
			if !strings.Contains(dnsKeys, legacyKey) {
				break
			}
			log.Infof("discovered legacy indexed DNS key (no interface scope): %s", legacyKey)
			keys = append(keys, legacyKey)
		}
	}

	return keys, nil
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
	localKey := getKeyWithInput(netbirdDNSStateKeyFormat, s.interfaceName, localSuffix)
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
	dnsServiceKey := fmt.Sprintf(primaryServiceStateKeyFormat, primaryServiceKey)
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
				// Prefer the first IPv4 server as ServerIP since our DNS listener is IPv4.
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
		key := fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, s.interfaceName, suffix, i)
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

func getKeyWithInput(format, iface, key string) string {
	return fmt.Sprintf(format, iface, key)
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
	// Capture stdout and stderr into separate buffers so the parser only
	// sees stdout (and stderr can be surfaced in the error without
	// interleaving parser input).
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if isScutilFailure(stdout.Bytes(), stderr.Bytes()) {
		return nil, fmt.Errorf("running system configuration command: %q, scutil error: stdout=%q stderr=%q", command, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
	}
	if err != nil {
		return nil, fmt.Errorf("running system configuration command: %q, error: %w, stdout=%q stderr=%q", command, err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// isScutilFailure reports whether scutil output indicates it could not perform the requested operation,
// even though the process exited 0.
// scutil has been observed to print "Permission denied" to stdout and still exit 0,
// which would otherwise cause a silent no-op to be treated as success.
//
// "Permission denied" and "Operation not permitted" are matched as whole, case-insensitive lines.
// "Could not open..." is a prefix match because the suffix varies ("configuration daemon socket" and friends).
// Substring scanning (e.g. for "permission" or "denied")
// would misclassify legitimate output that contains those words,
// such as a domain or key name like "permission-test.example.com".
func isScutilFailure(stdout, stderr []byte) bool {
	for _, buf := range [][]byte{stdout, stderr} {
		scanner := bufio.NewScanner(bytes.NewReader(buf))
		for scanner.Scan() {
			line := strings.TrimSuffix(strings.TrimSpace(scanner.Text()), ".")
			switch {
			case strings.EqualFold(line, "Permission denied"):
				return true
			case strings.EqualFold(line, "Operation not permitted"):
				return true
			case strings.HasPrefix(strings.ToLower(line), "could not open"):
				return true
			}
		}
	}
	return false
}
