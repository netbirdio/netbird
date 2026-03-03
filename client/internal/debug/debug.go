package debug

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"slices"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/updatemanager/installer"
	nbstatus "github.com/netbirdio/netbird/client/status"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/version"
)

const readmeContent = `Netbird debug bundle
This debug bundle contains the following files.
If the --anonymize flag is set, the files are anonymized to protect sensitive information.

status.txt: Anonymized status information of the NetBird client.
client.log: Most recent, anonymized client log file of the NetBird client.
netbird.err: Most recent, anonymized stderr log file of the NetBird client.
netbird.out: Most recent, anonymized stdout log file of the NetBird client.
routes.txt: Detailed system routing table in tabular format including destination, gateway, interface, metrics, and protocol information, if --system-info flag was provided.
interfaces.txt: Anonymized network interface information, if --system-info flag was provided.
ip_rules.txt: Detailed IP routing rules in tabular format including priority, source, destination, interfaces, table, and action information (Linux only), if --system-info flag was provided.
iptables.txt: Anonymized iptables rules with packet counters, if --system-info flag was provided.
nftables.txt: Anonymized nftables rules with packet counters, if --system-info flag was provided.
resolv.conf: DNS resolver configuration from /etc/resolv.conf (Unix systems only), if --system-info flag was provided.
scutil_dns.txt: DNS configuration from scutil --dns (macOS only), if --system-info flag was provided.
resolved_domains.txt: Anonymized resolved domain IP addresses from the status recorder.
config.txt: Anonymized configuration information of the NetBird client.
network_map.json: Anonymized sync response containing peer configurations, routes, DNS settings, and firewall rules.
state.json: Anonymized client state dump containing netbird states for the active profile.
mutex.prof: Mutex profiling information.
goroutine.prof: Goroutine profiling information.
block.prof: Block profiling information.
heap.prof: Heap profiling information (snapshot of memory allocations).
allocs.prof: Allocations profiling information.
threadcreate.prof: Thread creation profiling information.
cpu.prof: CPU profiling information.
stack_trace.txt: Complete stack traces of all goroutines at the time of bundle creation.


Anonymization Process
The files in this bundle have been anonymized to protect sensitive information. Here's how the anonymization was applied:

IP Addresses

IPv4 addresses are replaced with addresses starting from 198.51.100.0
IPv6 addresses are replaced with addresses starting from 100::

IP addresses from non public ranges and well known addresses are not anonymized (e.g. 8.8.8.8, 100.64.0.0/10, addresses starting with 192.168., 172.16., 10., etc.).
Reoccuring IP addresses are replaced with the same anonymized address.

Note: The anonymized IP addresses in the status file do not match those in the log and routes files. However, the anonymized IP addresses are consistent within the status file and across the routes and log files.

Domains
All domain names (except for the netbird domains) are replaced with randomly generated strings ending in ".domain". Anonymized domains are consistent across all files in the bundle.
Reoccuring domain names are replaced with the same anonymized domain.

Sync Response
The network_map.json file contains the following anonymized information:
- Peer configurations (addresses, FQDNs, DNS settings)
- Remote and offline peer information (allowed IPs, FQDNs)
- Routes (network ranges, associated domains)
- DNS configuration (nameservers, domains, custom zones)
- Firewall rules (peer IPs, source/destination ranges)

SSH keys in the sync response are replaced with a placeholder value. All IP addresses and domains in the sync response follow the same anonymization rules as described above.

State File
The state.json file contains anonymized internal state information of the NetBird client, including:
- DNS settings and configuration
- Firewall rules
- Exclusion routes
- Route selection
- Other internal states that may be present

The state file follows the same anonymization rules as other files:
- IP addresses (both individual and CIDR ranges) are anonymized while preserving their structure
- Domain names are consistently anonymized
- Technical identifiers and non-sensitive data remain unchanged

Mutex, Goroutines, Block, and Heap Profiling Files
The goroutine, block, mutex, and heap profiling files contain process information that might help the NetBird team diagnose performance or memory issues. The information in these files doesn't contain personal data.
You can check each using the following go command:

go tool pprof -http=:8088 <profile_name>.prof

For example, to view the heap profile:
go tool pprof -http=:8088 heap.prof

This will open a web browser tab with the profiling information.

Stack Trace
The stack_trace.txt file contains a complete snapshot of all goroutine stack traces at the time the debug bundle was created.

Routes
The routes.txt file contains detailed routing table information in a tabular format:

- Destination: Network prefix (IP_ADDRESS/PREFIX_LENGTH)
- Gateway: Next hop IP address (or "-" if direct)
- Interface: Network interface name
- Metric: Route priority/metric (lower values preferred)
- Protocol: Routing protocol (kernel, static, dhcp, etc.)
- Scope: Route scope (global, link, host, etc.)
- Type: Route type (unicast, local, broadcast, etc.)
- Table: Routing table name (main, local, netbird, etc.)

The table format provides a comprehensive view of the system's routing configuration, including information from multiple routing tables on Linux systems. This is valuable for troubleshooting routing issues and understanding traffic flow.

For anonymized routes, IP addresses are replaced as described above. The prefix length remains unchanged. Note that for prefixes, the anonymized IP might not be a network address, but the prefix length is still correct. Interface names are anonymized using string anonymization.

Resolved Domains
The resolved_domains.txt file contains information about domain names that have been resolved to IP addresses by NetBird's DNS resolver. This includes:
- Original domain patterns that were configured for routing
- Resolved domain names that matched those patterns
- IP address prefixes that were resolved for each domain
- Parent domain associations showing which original pattern each resolved domain belongs to

All domain names and IP addresses in this file follow the same anonymization rules as described above. This information is valuable for troubleshooting DNS resolution and routing issues.

Network Interfaces
The interfaces.txt file contains information about network interfaces, including:
- Interface name
- Interface index
- MTU (Maximum Transmission Unit)
- Flags
- IP addresses associated with each interface

The IP addresses in the interfaces file are anonymized using the same process as described above. Interface names, indexes, MTUs, and flags are not anonymized.

Configuration
The config.txt file contains anonymized configuration information of the NetBird client. Sensitive information such as private keys and SSH keys are excluded. The following fields are anonymized:
- ManagementURL
- AdminURL
- NATExternalIPs
- CustomDNSAddress

Other non-sensitive configuration options are included without anonymization.

Firewall Rules (Linux only)
The bundle includes two separate firewall rule files:

iptables.txt:
- Complete iptables ruleset with packet counters using 'iptables -v -n -L'
- Includes all tables (filter, nat, mangle, raw, security)
- Shows packet and byte counters for each rule
- All IP addresses are anonymized
- Chain names, table names, and other non-sensitive information remain unchanged

nftables.txt:
- Complete nftables ruleset obtained via 'nft -a list ruleset'
- Includes rule handle numbers and packet counters
- All tables, chains, and rules are included
- Shows packet and byte counters for each rule
- All IP addresses are anonymized
- Chain names, table names, and other non-sensitive information remain unchanged

IP Rules (Linux only)
The ip_rules.txt file contains detailed IP routing rule information:

- Priority: Rule priority number (lower values processed first)
- From: Source IP prefix or "all" if unspecified
- To: Destination IP prefix or "all" if unspecified
- IIF: Input interface name or "-" if unspecified
- OIF: Output interface name or "-" if unspecified
- Table: Target routing table name (main, local, netbird, etc.)
- Action: Rule action (lookup, goto, blackhole, etc.)
- Mark: Firewall mark value in hex format or "-" if unspecified

The table format provides comprehensive visibility into the IP routing decision process, including how traffic is directed to different routing tables based on various criteria. This is valuable for troubleshooting advanced routing configurations and policy-based routing.

For anonymized rules, IP addresses and prefixes are replaced as described above. Interface names are anonymized using string anonymization. Table names, actions, and other non-sensitive information remain unchanged.

DNS Configuration
The debug bundle includes platform-specific DNS configuration files:

resolv.conf (Unix systems):
- Contains DNS resolver configuration from /etc/resolv.conf
- Includes nameserver entries, search domains, and resolver options
- All IP addresses and domain names are anonymized following the same rules as other files

scutil_dns.txt (macOS only):
- Contains detailed DNS configuration from scutil --dns
- Shows DNS configuration for all network interfaces
- Includes search domains, nameservers, and DNS resolver settings
- All IP addresses and domain names are anonymized
`

const (
	clientLogFile = "client.log"
	errorLogFile  = "netbird.err"
	stdoutLogFile = "netbird.out"

	darwinErrorLogPath  = "/var/log/netbird.out.log"
	darwinStdoutLogPath = "/var/log/netbird.err.log"
)

type BundleGenerator struct {
	anonymizer *anonymize.Anonymizer

	// deps
	internalConfig *profilemanager.Config
	statusRecorder *peer.Status
	syncResponse   *mgmProto.SyncResponse
	logPath        string
	cpuProfile     []byte
	refreshStatus  func() // Optional callback to refresh status before bundle generation

	anonymize         bool
	includeSystemInfo bool
	logFileCount      uint32

	archive *zip.Writer
}

type BundleConfig struct {
	Anonymize         bool
	IncludeSystemInfo bool
	LogFileCount      uint32
}

type GeneratorDependencies struct {
	InternalConfig *profilemanager.Config
	StatusRecorder *peer.Status
	SyncResponse   *mgmProto.SyncResponse
	LogPath        string
	CPUProfile     []byte
	RefreshStatus  func() // Optional callback to refresh status before bundle generation
}

func NewBundleGenerator(deps GeneratorDependencies, cfg BundleConfig) *BundleGenerator {
	// Default to 1 log file for backward compatibility when 0 is provided
	logFileCount := cfg.LogFileCount
	if logFileCount == 0 {
		logFileCount = 1
	}

	return &BundleGenerator{
		anonymizer: anonymize.NewAnonymizer(anonymize.DefaultAddresses()),

		internalConfig: deps.InternalConfig,
		statusRecorder: deps.StatusRecorder,
		syncResponse:   deps.SyncResponse,
		logPath:        deps.LogPath,
		cpuProfile:     deps.CPUProfile,
		refreshStatus:  deps.RefreshStatus,

		anonymize:         cfg.Anonymize,
		includeSystemInfo: cfg.IncludeSystemInfo,
		logFileCount:      logFileCount,
	}
}

// Generate creates a debug bundle and returns the location.
func (g *BundleGenerator) Generate() (resp string, err error) {
	bundlePath, err := os.CreateTemp("", "netbird.debug.*.zip")
	if err != nil {
		return "", fmt.Errorf("create zip file: %w", err)
	}
	defer func() {
		if closeErr := bundlePath.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close zip file: %w", closeErr)
		}

		if err != nil {
			if removeErr := os.Remove(bundlePath.Name()); removeErr != nil {
				log.Errorf("Failed to remove zip file: %v", removeErr)
			}
		}
	}()

	g.archive = zip.NewWriter(bundlePath)

	if err := g.createArchive(); err != nil {
		return "", err
	}

	if err := g.archive.Close(); err != nil {
		return "", fmt.Errorf("close archive writer: %w", err)
	}

	return bundlePath.Name(), nil
}

func (g *BundleGenerator) createArchive() error {
	if err := g.addReadme(); err != nil {
		return fmt.Errorf("add readme: %w", err)
	}

	if err := g.addStatus(); err != nil {
		return fmt.Errorf("add status: %w", err)
	}

	if err := g.addConfig(); err != nil {
		log.Errorf("failed to add config to debug bundle: %v", err)
	}

	if err := g.addResolvedDomains(); err != nil {
		log.Errorf("failed to add resolved domains to debug bundle: %v", err)
	}

	if g.includeSystemInfo {
		g.addSystemInfo()
	}

	if err := g.addProf(); err != nil {
		log.Errorf("failed to add profiles to debug bundle: %v", err)
	}

	if err := g.addCPUProfile(); err != nil {
		log.Errorf("failed to add CPU profile to debug bundle: %v", err)
	}

	if err := g.addStackTrace(); err != nil {
		log.Errorf("failed to add stack trace to debug bundle: %v", err)
	}

	if err := g.addSyncResponse(); err != nil {
		return fmt.Errorf("add sync response: %w", err)
	}

	if err := g.addStateFile(); err != nil {
		log.Errorf("failed to add state file to debug bundle: %v", err)
	}

	if err := g.addCorruptedStateFiles(); err != nil {
		log.Errorf("failed to add corrupted state files to debug bundle: %v", err)
	}

	if err := g.addWgShow(); err != nil {
		log.Errorf("failed to add wg show output: %v", err)
	}

	if g.logPath != "" && !slices.Contains(util.SpecialLogs, g.logPath) {
		if err := g.addLogfile(); err != nil {
			log.Errorf("failed to add log file to debug bundle: %v", err)
			if err := g.trySystemdLogFallback(); err != nil {
				log.Errorf("failed to add systemd logs as fallback: %v", err)
			}
		}
	} else if err := g.trySystemdLogFallback(); err != nil {
		log.Errorf("failed to add systemd logs: %v", err)
	}

	if err := g.addUpdateLogs(); err != nil {
		log.Errorf("failed to add updater logs: %v", err)
	}

	return nil
}

func (g *BundleGenerator) addSystemInfo() {
	if err := g.addRoutes(); err != nil {
		log.Errorf("failed to add routes to debug bundle: %v", err)
	}

	if err := g.addInterfaces(); err != nil {
		log.Errorf("failed to add interfaces to debug bundle: %v", err)
	}

	if err := g.addIPRules(); err != nil {
		log.Errorf("failed to add IP rules to debug bundle: %v", err)
	}

	if err := g.addFirewallRules(); err != nil {
		log.Errorf("failed to add firewall rules to debug bundle: %v", err)
	}

	if err := g.addDNSInfo(); err != nil {
		log.Errorf("failed to add DNS info to debug bundle: %v", err)
	}
}

func (g *BundleGenerator) addReadme() error {
	readmeReader := strings.NewReader(readmeContent)
	if err := g.addFileToZip(readmeReader, "README.txt"); err != nil {
		return fmt.Errorf("add README file to zip: %w", err)
	}
	return nil
}

func (g *BundleGenerator) addStatus() error {
	if g.statusRecorder != nil {
		pm := profilemanager.NewProfileManager()
		var profName string
		if activeProf, err := pm.GetActiveProfile(); err == nil {
			profName = activeProf.Name
		}

		if g.refreshStatus != nil {
			g.refreshStatus()
		}

		fullStatus := g.statusRecorder.GetFullStatus()
		protoFullStatus := nbstatus.ToProtoFullStatus(fullStatus)
		protoFullStatus.Events = g.statusRecorder.GetEventHistory()
		overview := nbstatus.ConvertToStatusOutputOverview(protoFullStatus, g.anonymize, version.NetbirdVersion(), "", nil, nil, nil, "", profName)
		statusOutput := overview.FullDetailSummary()

		statusReader := strings.NewReader(statusOutput)
		if err := g.addFileToZip(statusReader, "status.txt"); err != nil {
			return fmt.Errorf("add status file to zip: %w", err)
		}
		seedFromStatus(g.anonymizer, &fullStatus)
	} else {
		log.Debugf("no status recorder available for seeding")
	}
	return nil
}

func (g *BundleGenerator) addConfig() error {
	if g.internalConfig == nil {
		log.Debug("skipping empty config in debug bundle")
		return nil
	}

	var configContent strings.Builder
	g.addCommonConfigFields(&configContent)

	if g.anonymize {
		if g.internalConfig.ManagementURL != nil {
			configContent.WriteString(fmt.Sprintf("ManagementURL: %s\n", g.anonymizer.AnonymizeURI(g.internalConfig.ManagementURL.String())))
		}
		if g.internalConfig.AdminURL != nil {
			configContent.WriteString(fmt.Sprintf("AdminURL: %s\n", g.anonymizer.AnonymizeURI(g.internalConfig.AdminURL.String())))
		}
		configContent.WriteString(fmt.Sprintf("NATExternalIPs: %v\n", anonymizeNATExternalIPs(g.internalConfig.NATExternalIPs, g.anonymizer)))
		if g.internalConfig.CustomDNSAddress != "" {
			configContent.WriteString(fmt.Sprintf("CustomDNSAddress: %s\n", g.anonymizer.AnonymizeString(g.internalConfig.CustomDNSAddress)))
		}
	} else {
		if g.internalConfig.ManagementURL != nil {
			configContent.WriteString(fmt.Sprintf("ManagementURL: %s\n", g.internalConfig.ManagementURL.String()))
		}
		if g.internalConfig.AdminURL != nil {
			configContent.WriteString(fmt.Sprintf("AdminURL: %s\n", g.internalConfig.AdminURL.String()))
		}
		configContent.WriteString(fmt.Sprintf("NATExternalIPs: %v\n", g.internalConfig.NATExternalIPs))
		if g.internalConfig.CustomDNSAddress != "" {
			configContent.WriteString(fmt.Sprintf("CustomDNSAddress: %s\n", g.internalConfig.CustomDNSAddress))
		}
	}

	configReader := strings.NewReader(configContent.String())
	if err := g.addFileToZip(configReader, "config.txt"); err != nil {
		return fmt.Errorf("add config file to zip: %w", err)
	}

	return nil
}

func (g *BundleGenerator) addCommonConfigFields(configContent *strings.Builder) {
	configContent.WriteString("NetBird Client Configuration:\n\n")

	configContent.WriteString(fmt.Sprintf("WgIface: %s\n", g.internalConfig.WgIface))
	configContent.WriteString(fmt.Sprintf("WgPort: %d\n", g.internalConfig.WgPort))
	if g.internalConfig.NetworkMonitor != nil {
		configContent.WriteString(fmt.Sprintf("NetworkMonitor: %v\n", *g.internalConfig.NetworkMonitor))
	}
	configContent.WriteString(fmt.Sprintf("IFaceBlackList: %v\n", g.internalConfig.IFaceBlackList))
	configContent.WriteString(fmt.Sprintf("DisableIPv6Discovery: %v\n", g.internalConfig.DisableIPv6Discovery))
	configContent.WriteString(fmt.Sprintf("RosenpassEnabled: %v\n", g.internalConfig.RosenpassEnabled))
	configContent.WriteString(fmt.Sprintf("RosenpassPermissive: %v\n", g.internalConfig.RosenpassPermissive))
	if g.internalConfig.ServerSSHAllowed != nil {
		configContent.WriteString(fmt.Sprintf("ServerSSHAllowed: %v\n", *g.internalConfig.ServerSSHAllowed))
	}
	if g.internalConfig.EnableSSHRoot != nil {
		configContent.WriteString(fmt.Sprintf("EnableSSHRoot: %v\n", *g.internalConfig.EnableSSHRoot))
	}
	if g.internalConfig.EnableSSHSFTP != nil {
		configContent.WriteString(fmt.Sprintf("EnableSSHSFTP: %v\n", *g.internalConfig.EnableSSHSFTP))
	}
	if g.internalConfig.EnableSSHLocalPortForwarding != nil {
		configContent.WriteString(fmt.Sprintf("EnableSSHLocalPortForwarding: %v\n", *g.internalConfig.EnableSSHLocalPortForwarding))
	}
	if g.internalConfig.EnableSSHRemotePortForwarding != nil {
		configContent.WriteString(fmt.Sprintf("EnableSSHRemotePortForwarding: %v\n", *g.internalConfig.EnableSSHRemotePortForwarding))
	}

	configContent.WriteString(fmt.Sprintf("DisableClientRoutes: %v\n", g.internalConfig.DisableClientRoutes))
	configContent.WriteString(fmt.Sprintf("DisableServerRoutes: %v\n", g.internalConfig.DisableServerRoutes))
	configContent.WriteString(fmt.Sprintf("DisableDNS: %v\n", g.internalConfig.DisableDNS))
	configContent.WriteString(fmt.Sprintf("DisableFirewall: %v\n", g.internalConfig.DisableFirewall))
	configContent.WriteString(fmt.Sprintf("BlockLANAccess: %v\n", g.internalConfig.BlockLANAccess))
	configContent.WriteString(fmt.Sprintf("BlockInbound: %v\n", g.internalConfig.BlockInbound))

	if g.internalConfig.DisableNotifications != nil {
		configContent.WriteString(fmt.Sprintf("DisableNotifications: %v\n", *g.internalConfig.DisableNotifications))
	}

	configContent.WriteString(fmt.Sprintf("DNSLabels: %v\n", g.internalConfig.DNSLabels))

	configContent.WriteString(fmt.Sprintf("DisableAutoConnect: %v\n", g.internalConfig.DisableAutoConnect))

	configContent.WriteString(fmt.Sprintf("DNSRouteInterval: %s\n", g.internalConfig.DNSRouteInterval))

	if g.internalConfig.ClientCertPath != "" {
		configContent.WriteString(fmt.Sprintf("ClientCertPath: %s\n", g.internalConfig.ClientCertPath))
	}
	if g.internalConfig.ClientCertKeyPath != "" {
		configContent.WriteString(fmt.Sprintf("ClientCertKeyPath: %s\n", g.internalConfig.ClientCertKeyPath))
	}

	configContent.WriteString(fmt.Sprintf("LazyConnectionEnabled: %v\n", g.internalConfig.LazyConnectionEnabled))
}

func (g *BundleGenerator) addProf() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic while profiling: %v", r)
		}
	}()

	runtime.SetBlockProfileRate(1)
	_ = runtime.SetMutexProfileFraction(1)
	defer runtime.SetBlockProfileRate(0)
	defer runtime.SetMutexProfileFraction(0)

	time.Sleep(5 * time.Second)

	for _, profile := range []string{"goroutine", "block", "mutex", "heap", "allocs", "threadcreate"} {
		var buff []byte
		myBuff := bytes.NewBuffer(buff)
		err := pprof.Lookup(profile).WriteTo(myBuff, 0)
		if err != nil {
			return fmt.Errorf("write %s profile: %w", profile, err)
		}

		if err := g.addFileToZip(myBuff, profile+".prof"); err != nil {
			return fmt.Errorf("add %s file to zip: %w", profile, err)
		}
	}
	return nil
}

func (g *BundleGenerator) addCPUProfile() error {
	if len(g.cpuProfile) == 0 {
		return nil
	}

	reader := bytes.NewReader(g.cpuProfile)
	if err := g.addFileToZip(reader, "cpu.prof"); err != nil {
		return fmt.Errorf("add CPU profile to zip: %w", err)
	}

	return nil
}

func (g *BundleGenerator) addStackTrace() error {
	buf := make([]byte, 5242880) // 5 MB buffer
	n := runtime.Stack(buf, true)

	stackTrace := bytes.NewReader(buf[:n])
	if err := g.addFileToZip(stackTrace, "stack_trace.txt"); err != nil {
		return fmt.Errorf("add stack trace file to zip: %w", err)
	}

	return nil
}

func (g *BundleGenerator) addInterfaces() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("get interfaces: %w", err)
	}

	interfacesContent := formatInterfaces(interfaces, g.anonymize, g.anonymizer)
	interfacesReader := strings.NewReader(interfacesContent)
	if err := g.addFileToZip(interfacesReader, "interfaces.txt"); err != nil {
		return fmt.Errorf("add interfaces file to zip: %w", err)
	}

	return nil
}

func (g *BundleGenerator) addResolvedDomains() error {
	if g.statusRecorder == nil {
		log.Debugf("skipping resolved domains in debug bundle: no status recorder")
		return nil
	}

	resolvedDomains := g.statusRecorder.GetResolvedDomainsStates()
	if len(resolvedDomains) == 0 {
		log.Debugf("skipping resolved domains in debug bundle: no resolved domains")
		return nil
	}

	resolvedDomainsContent := formatResolvedDomains(resolvedDomains, g.anonymize, g.anonymizer)
	resolvedDomainsReader := strings.NewReader(resolvedDomainsContent)
	if err := g.addFileToZip(resolvedDomainsReader, "resolved_domains.txt"); err != nil {
		return fmt.Errorf("add resolved domains file to zip: %w", err)
	}

	return nil
}

func (g *BundleGenerator) addSyncResponse() error {
	if g.syncResponse == nil {
		log.Debugf("skipping empty sync response in debug bundle")
		return nil
	}

	if g.anonymize {
		if err := anonymizeSyncResponse(g.syncResponse, g.anonymizer); err != nil {
			return fmt.Errorf("anonymize sync response: %w", err)
		}
	}

	options := protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
		Indent:          "  ",
		AllowPartial:    true,
	}

	jsonBytes, err := options.Marshal(g.syncResponse)
	if err != nil {
		return fmt.Errorf("generate json: %w", err)
	}

	if err := g.addFileToZip(bytes.NewReader(jsonBytes), "network_map.json"); err != nil {
		return fmt.Errorf("add sync response to zip: %w", err)
	}

	return nil
}

func (g *BundleGenerator) addStateFile() error {
	sm := profilemanager.NewServiceManager("")
	path := sm.GetStatePath()
	if path == "" {
		return nil
	}

	log.Debugf("Adding state file from: %s", path)

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read state file: %w", err)
	}

	if g.anonymize {
		var rawStates map[string]json.RawMessage
		if err := json.Unmarshal(data, &rawStates); err != nil {
			return fmt.Errorf("unmarshal states: %w", err)
		}

		if err := anonymizeStateFile(&rawStates, g.anonymizer); err != nil {
			return fmt.Errorf("anonymize state file: %w", err)
		}

		bs, err := json.MarshalIndent(rawStates, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal states: %w", err)
		}
		data = bs
	}

	if err := g.addFileToZip(bytes.NewReader(data), "state.json"); err != nil {
		return fmt.Errorf("add state file to zip: %w", err)
	}

	return nil
}

func (g *BundleGenerator) addUpdateLogs() error {
	inst := installer.New()
	logFiles := inst.LogFiles()
	if len(logFiles) == 0 {
		return nil
	}

	log.Infof("adding updater logs")
	for _, logFile := range logFiles {
		data, err := os.ReadFile(logFile)
		if err != nil {
			log.Warnf("failed to read update log file %s: %v", logFile, err)
			continue
		}

		baseName := filepath.Base(logFile)
		if err := g.addFileToZip(bytes.NewReader(data), filepath.Join("update-logs", baseName)); err != nil {
			return fmt.Errorf("add update log file %s to zip: %w", baseName, err)
		}
	}
	return nil
}

func (g *BundleGenerator) addCorruptedStateFiles() error {
	sm := profilemanager.NewServiceManager("")
	pattern := sm.GetStatePath()
	if pattern == "" {
		return nil
	}
	pattern += "*.corrupted.*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("find corrupted state files: %w", err)
	}

	for _, match := range matches {
		data, err := os.ReadFile(match)
		if err != nil {
			log.Warnf("Failed to read corrupted state file %s: %v", match, err)
			continue
		}

		fileName := filepath.Base(match)
		if err := g.addFileToZip(bytes.NewReader(data), "corrupted_states/"+fileName); err != nil {
			log.Warnf("Failed to add corrupted state file %s to zip: %v", fileName, err)
			continue
		}

		log.Debugf("Added corrupted state file to debug bundle: %s", fileName)
	}

	return nil
}

func (g *BundleGenerator) addLogfile() error {
	if g.logPath == "" {
		log.Debugf("skipping empty log file in debug bundle")
		return nil
	}

	logDir := filepath.Dir(g.logPath)

	if err := g.addSingleLogfile(g.logPath, clientLogFile); err != nil {
		return fmt.Errorf("add client log file to zip: %w", err)
	}

	g.addRotatedLogFiles(logDir)

	stdErrLogPath := filepath.Join(logDir, errorLogFile)
	stdoutLogPath := filepath.Join(logDir, stdoutLogFile)
	if runtime.GOOS == "darwin" {
		stdErrLogPath = darwinErrorLogPath
		stdoutLogPath = darwinStdoutLogPath
	}

	if err := g.addSingleLogfile(stdErrLogPath, errorLogFile); err != nil {
		log.Warnf("Failed to add %s to zip: %v", errorLogFile, err)
	}

	if err := g.addSingleLogfile(stdoutLogPath, stdoutLogFile); err != nil {
		log.Warnf("Failed to add %s to zip: %v", stdoutLogFile, err)
	}

	return nil
}

// addSingleLogfile adds a single log file to the archive
func (g *BundleGenerator) addSingleLogfile(logPath, targetName string) error {
	logFile, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", targetName, err)
	}
	defer func() {
		if err := logFile.Close(); err != nil {
			log.Errorf("failed to close log file %s: %v", targetName, err)
		}
	}()

	var logReader io.Reader = logFile
	if g.anonymize {
		var writer *io.PipeWriter
		logReader, writer = io.Pipe()

		go anonymizeLog(logFile, writer, g.anonymizer)
	}
	if err := g.addFileToZip(logReader, targetName); err != nil {
		return fmt.Errorf("add %s to zip: %w", targetName, err)
	}

	return nil
}

// addSingleLogFileGz adds a single gzipped log file to the archive
func (g *BundleGenerator) addSingleLogFileGz(logPath, targetName string) error {
	f, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open gz log file %s: %w", targetName, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close gz file %s: %v", targetName, err)
		}
	}()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer func() {
		if err := gzr.Close(); err != nil {
			log.Errorf("failed to close gzip reader %s: %v", targetName, err)
		}
	}()

	var logReader io.Reader = gzr
	if g.anonymize {
		var pw *io.PipeWriter
		logReader, pw = io.Pipe()
		go anonymizeLog(gzr, pw, g.anonymizer)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := io.Copy(gw, logReader); err != nil {
		return fmt.Errorf("re-gzip: %w", err)
	}

	if err := gw.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}

	if err := g.addFileToZip(&buf, targetName); err != nil {
		return fmt.Errorf("add anonymized gz: %w", err)
	}

	return nil
}

// addRotatedLogFiles adds rotated log files to the bundle based on logFileCount
func (g *BundleGenerator) addRotatedLogFiles(logDir string) {
	if g.logFileCount == 0 {
		return
	}

	pattern := filepath.Join(logDir, "client-*.log.gz")
	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Warnf("failed to glob rotated logs: %v", err)
		return
	}

	if len(files) == 0 {
		return
	}

	// sort files by modification time (newest first)
	sort.Slice(files, func(i, j int) bool {
		fi, err := os.Stat(files[i])
		if err != nil {
			log.Warnf("failed to stat rotated log %s: %v", files[i], err)
			return false
		}
		fj, err := os.Stat(files[j])
		if err != nil {
			log.Warnf("failed to stat rotated log %s: %v", files[j], err)
			return false
		}
		return fi.ModTime().After(fj.ModTime())
	})

	maxFiles := int(g.logFileCount)
	if maxFiles > len(files) {
		maxFiles = len(files)
	}

	for i := 0; i < maxFiles; i++ {
		name := filepath.Base(files[i])
		if err := g.addSingleLogFileGz(files[i], name); err != nil {
			log.Warnf("failed to add rotated log %s: %v", name, err)
		}
	}
}

func (g *BundleGenerator) addFileToZip(reader io.Reader, filename string) error {
	header := &zip.FileHeader{
		Name:     filename,
		Method:   zip.Deflate,
		Modified: time.Now(),

		CreatorVersion: 20,    // Version 2.0
		ReaderVersion:  20,    // Version 2.0
		Flags:          0x800, // UTF-8 filename
	}

	// If the reader is a file, we can get more accurate information
	if f, ok := reader.(*os.File); ok {
		if stat, err := f.Stat(); err != nil {
			log.Tracef("failed to get file stat for %s: %v", filename, err)
		} else {
			header.Modified = stat.ModTime()
		}
	}

	writer, err := g.archive.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create zip file header: %w", err)
	}

	if _, err := io.Copy(writer, reader); err != nil {
		return fmt.Errorf("write file to zip: %w", err)
	}

	return nil
}

func seedFromStatus(a *anonymize.Anonymizer, status *peer.FullStatus) {
	status.ManagementState.URL = a.AnonymizeURI(status.ManagementState.URL)
	status.SignalState.URL = a.AnonymizeURI(status.SignalState.URL)

	status.LocalPeerState.FQDN = a.AnonymizeDomain(status.LocalPeerState.FQDN)

	for _, p := range status.Peers {
		a.AnonymizeDomain(p.FQDN)
		for route := range p.GetRoutes() {
			a.AnonymizeRoute(route)
		}
	}

	for route := range status.LocalPeerState.Routes {
		a.AnonymizeRoute(route)
	}

	for _, nsGroup := range status.NSGroupStates {
		for _, domain := range nsGroup.Domains {
			a.AnonymizeDomain(domain)
		}
	}

	for _, relay := range status.Relays {
		if relay.URI != "" {
			a.AnonymizeURI(relay.URI)
		}
	}
}

func anonymizeLog(reader io.Reader, writer *io.PipeWriter, anonymizer *anonymize.Anonymizer) {
	defer func() {
		// always nil
		_ = writer.Close()
	}()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := anonymizer.AnonymizeString(scanner.Text())
		if _, err := writer.Write([]byte(line + "\n")); err != nil {
			if err := writer.CloseWithError(fmt.Errorf("anonymize write: %w", err)); err != nil {
				log.Errorf("Failed to close writer: %v", err)
			}
			return
		}
	}
	if err := scanner.Err(); err != nil {
		if err := writer.CloseWithError(fmt.Errorf("anonymize scan: %w", err)); err != nil {
			log.Errorf("Failed to close writer: %v", err)
		}
		return
	}
}

func anonymizeNATExternalIPs(ips []string, anonymizer *anonymize.Anonymizer) []string {
	anonymizedIPs := make([]string, len(ips))
	for i, ip := range ips {
		parts := strings.SplitN(ip, "/", 2)

		ip1, err := netip.ParseAddr(parts[0])
		if err != nil {
			anonymizedIPs[i] = ip
			continue
		}
		ip1anon := anonymizer.AnonymizeIP(ip1)

		if len(parts) == 2 {
			ip2, err := netip.ParseAddr(parts[1])
			if err != nil {
				anonymizedIPs[i] = fmt.Sprintf("%s/%s", ip1anon, parts[1])
			} else {
				ip2anon := anonymizer.AnonymizeIP(ip2)
				anonymizedIPs[i] = fmt.Sprintf("%s/%s", ip1anon, ip2anon)
			}
		} else {
			anonymizedIPs[i] = ip1anon.String()
		}
	}
	return anonymizedIPs
}

func anonymizeNetworkMap(networkMap *mgmProto.NetworkMap, anonymizer *anonymize.Anonymizer) error {
	if networkMap.PeerConfig != nil {
		anonymizePeerConfig(networkMap.PeerConfig, anonymizer)
	}

	for _, p := range networkMap.RemotePeers {
		anonymizeRemotePeer(p, anonymizer)
	}

	for _, p := range networkMap.OfflinePeers {
		anonymizeRemotePeer(p, anonymizer)
	}

	for _, r := range networkMap.Routes {
		anonymizeRoute(r, anonymizer)
	}

	if networkMap.DNSConfig != nil {
		anonymizeDNSConfig(networkMap.DNSConfig, anonymizer)
	}

	for _, rule := range networkMap.FirewallRules {
		anonymizeFirewallRule(rule, anonymizer)
	}

	for _, rule := range networkMap.RoutesFirewallRules {
		anonymizeRouteFirewallRule(rule, anonymizer)
	}

	return nil
}

func anonymizeNetbirdConfig(config *mgmProto.NetbirdConfig, anonymizer *anonymize.Anonymizer) {
	for _, stun := range config.Stuns {
		if stun.Uri != "" {
			stun.Uri = anonymizer.AnonymizeURI(stun.Uri)
		}
	}

	for _, turn := range config.Turns {
		if turn.HostConfig != nil && turn.HostConfig.Uri != "" {
			turn.HostConfig.Uri = anonymizer.AnonymizeURI(turn.HostConfig.Uri)
		}
		if turn.User != "" {
			turn.User = "turn-user-placeholder"
		}
		if turn.Password != "" {
			turn.Password = "turn-password-placeholder"
		}
	}

	if config.Signal != nil && config.Signal.Uri != "" {
		config.Signal.Uri = anonymizer.AnonymizeURI(config.Signal.Uri)
	}

	if config.Relay != nil {
		for i, url := range config.Relay.Urls {
			config.Relay.Urls[i] = anonymizer.AnonymizeURI(url)
		}
		if config.Relay.TokenPayload != "" {
			config.Relay.TokenPayload = "relay-token-payload-placeholder"
		}
		if config.Relay.TokenSignature != "" {
			config.Relay.TokenSignature = "relay-token-signature-placeholder"
		}
	}

	if config.Flow != nil {
		if config.Flow.Url != "" {
			config.Flow.Url = anonymizer.AnonymizeURI(config.Flow.Url)
		}
		if config.Flow.TokenPayload != "" {
			config.Flow.TokenPayload = "flow-token-payload-placeholder"
		}
		if config.Flow.TokenSignature != "" {
			config.Flow.TokenSignature = "flow-token-signature-placeholder"
		}
	}
}

func anonymizeSyncResponse(syncResponse *mgmProto.SyncResponse, anonymizer *anonymize.Anonymizer) error {
	if syncResponse.NetbirdConfig != nil {
		anonymizeNetbirdConfig(syncResponse.NetbirdConfig, anonymizer)
	}

	if syncResponse.PeerConfig != nil {
		anonymizePeerConfig(syncResponse.PeerConfig, anonymizer)
	}

	for _, p := range syncResponse.RemotePeers {
		anonymizeRemotePeer(p, anonymizer)
	}

	if syncResponse.NetworkMap != nil {
		if err := anonymizeNetworkMap(syncResponse.NetworkMap, anonymizer); err != nil {
			return err
		}
	}

	for _, check := range syncResponse.Checks {
		for i, file := range check.Files {
			check.Files[i] = anonymizer.AnonymizeString(file)
		}
	}

	return nil
}

func anonymizeSSHConfig(sshConfig *mgmProto.SSHConfig) {
	if sshConfig != nil && len(sshConfig.SshPubKey) > 0 {
		sshConfig.SshPubKey = []byte("ssh-placeholder-key")
	}
}

func anonymizePeerConfig(config *mgmProto.PeerConfig, anonymizer *anonymize.Anonymizer) {
	if config == nil {
		return
	}

	if addr, err := netip.ParseAddr(config.Address); err == nil {
		config.Address = anonymizer.AnonymizeIP(addr).String()
	}

	anonymizeSSHConfig(config.SshConfig)

	config.Dns = anonymizer.AnonymizeString(config.Dns)
	config.Fqdn = anonymizer.AnonymizeDomain(config.Fqdn)
}

func anonymizeRemotePeer(peer *mgmProto.RemotePeerConfig, anonymizer *anonymize.Anonymizer) {
	if peer == nil {
		return
	}

	for i, ip := range peer.AllowedIps {
		if prefix, err := netip.ParsePrefix(ip); err == nil {
			anonIP := anonymizer.AnonymizeIP(prefix.Addr())
			peer.AllowedIps[i] = fmt.Sprintf("%s/%d", anonIP, prefix.Bits())
		} else if addr, err := netip.ParseAddr(ip); err == nil {
			peer.AllowedIps[i] = anonymizer.AnonymizeIP(addr).String()
		}
	}

	peer.Fqdn = anonymizer.AnonymizeDomain(peer.Fqdn)

	anonymizeSSHConfig(peer.SshConfig)
}

func anonymizeRoute(route *mgmProto.Route, anonymizer *anonymize.Anonymizer) {
	if route == nil {
		return
	}

	if prefix, err := netip.ParsePrefix(route.Network); err == nil {
		anonIP := anonymizer.AnonymizeIP(prefix.Addr())
		route.Network = fmt.Sprintf("%s/%d", anonIP, prefix.Bits())
	}

	for i, domain := range route.Domains {
		route.Domains[i] = anonymizer.AnonymizeDomain(domain)
	}

	route.NetID = anonymizer.AnonymizeString(route.NetID)
}

func anonymizeDNSConfig(config *mgmProto.DNSConfig, anonymizer *anonymize.Anonymizer) {
	if config == nil {
		return
	}

	anonymizeNameBundleGeneratorGroups(config.NameServerGroups, anonymizer)
	anonymizeCustomZones(config.CustomZones, anonymizer)
}

func anonymizeNameBundleGeneratorGroups(groups []*mgmProto.NameServerGroup, anonymizer *anonymize.Anonymizer) {
	for _, group := range groups {
		anonymizeBundleGenerators(group.NameServers, anonymizer)
		anonymizeDomains(group.Domains, anonymizer)
	}
}

func anonymizeBundleGenerators(servers []*mgmProto.NameServer, anonymizer *anonymize.Anonymizer) {
	for _, server := range servers {
		if addr, err := netip.ParseAddr(server.IP); err == nil {
			server.IP = anonymizer.AnonymizeIP(addr).String()
		}
	}
}

func anonymizeDomains(domains []string, anonymizer *anonymize.Anonymizer) {
	for i, domain := range domains {
		domains[i] = anonymizer.AnonymizeDomain(domain)
	}
}

func anonymizeCustomZones(zones []*mgmProto.CustomZone, anonymizer *anonymize.Anonymizer) {
	for _, zone := range zones {
		zone.Domain = anonymizer.AnonymizeDomain(zone.Domain)
		anonymizeRecords(zone.Records, anonymizer)
	}
}

func anonymizeRecords(records []*mgmProto.SimpleRecord, anonymizer *anonymize.Anonymizer) {
	for _, record := range records {
		record.Name = anonymizer.AnonymizeDomain(record.Name)
		anonymizeRData(record, anonymizer)
	}
}

func anonymizeRData(record *mgmProto.SimpleRecord, anonymizer *anonymize.Anonymizer) {
	switch record.Type {
	case 1, 28:
		if addr, err := netip.ParseAddr(record.RData); err == nil {
			record.RData = anonymizer.AnonymizeIP(addr).String()
		}
	default:
		record.RData = anonymizer.AnonymizeString(record.RData)
	}
}

func anonymizeFirewallRule(rule *mgmProto.FirewallRule, anonymizer *anonymize.Anonymizer) {
	if rule == nil {
		return
	}

	if addr, err := netip.ParseAddr(rule.PeerIP); err == nil {
		rule.PeerIP = anonymizer.AnonymizeIP(addr).String()
	}
}

func anonymizeRouteFirewallRule(rule *mgmProto.RouteFirewallRule, anonymizer *anonymize.Anonymizer) {
	if rule == nil {
		return
	}

	for i, sourceRange := range rule.SourceRanges {
		if prefix, err := netip.ParsePrefix(sourceRange); err == nil {
			anonIP := anonymizer.AnonymizeIP(prefix.Addr())
			rule.SourceRanges[i] = fmt.Sprintf("%s/%d", anonIP, prefix.Bits())
		}
	}

	if prefix, err := netip.ParsePrefix(rule.Destination); err == nil {
		anonIP := anonymizer.AnonymizeIP(prefix.Addr())
		rule.Destination = fmt.Sprintf("%s/%d", anonIP, prefix.Bits())
	}
}

func anonymizeStateFile(rawStates *map[string]json.RawMessage, anonymizer *anonymize.Anonymizer) error {
	for name, rawState := range *rawStates {
		if string(rawState) == "null" {
			continue
		}

		var state map[string]any
		if err := json.Unmarshal(rawState, &state); err != nil {
			return fmt.Errorf("unmarshal state %s: %w", name, err)
		}

		state = anonymizeValue(state, anonymizer).(map[string]any)

		bs, err := json.Marshal(state)
		if err != nil {
			return fmt.Errorf("marshal state %s: %w", name, err)
		}

		(*rawStates)[name] = bs
	}

	return nil
}

func anonymizeValue(value any, anonymizer *anonymize.Anonymizer) any {
	switch v := value.(type) {
	case string:
		return anonymizeString(v, anonymizer)
	case map[string]any:
		return anonymizeMap(v, anonymizer)
	case []any:
		return anonymizeSlice(v, anonymizer)
	}
	return value
}

func anonymizeString(v string, anonymizer *anonymize.Anonymizer) string {
	if prefix, err := netip.ParsePrefix(v); err == nil {
		anonIP := anonymizer.AnonymizeIP(prefix.Addr())
		return fmt.Sprintf("%s/%d", anonIP, prefix.Bits())
	}
	if ip, err := netip.ParseAddr(v); err == nil {
		return anonymizer.AnonymizeIP(ip).String()
	}
	return anonymizer.AnonymizeString(v)
}

func anonymizeMap(v map[string]any, anonymizer *anonymize.Anonymizer) map[string]any {
	result := make(map[string]any, len(v))
	for key, val := range v {
		newKey := anonymizeMapKey(key, anonymizer)
		result[newKey] = anonymizeValue(val, anonymizer)
	}
	return result
}

func anonymizeMapKey(key string, anonymizer *anonymize.Anonymizer) string {
	if prefix, err := netip.ParsePrefix(key); err == nil {
		anonIP := anonymizer.AnonymizeIP(prefix.Addr())
		return fmt.Sprintf("%s/%d", anonIP, prefix.Bits())
	}
	if ip, err := netip.ParseAddr(key); err == nil {
		return anonymizer.AnonymizeIP(ip).String()
	}
	return key
}

func anonymizeSlice(v []any, anonymizer *anonymize.Anonymizer) []any {
	for i, val := range v {
		v[i] = anonymizeValue(val, anonymizer)
	}
	return v
}
