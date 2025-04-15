//go:build !android && !ios

package server

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
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
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/proto"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

const readmeContent = `Netbird debug bundle
This debug bundle contains the following files.
If the --anonymize flag is set, the files are anonymized to protect sensitive information.

status.txt: Anonymized status information of the NetBird client.
client.log: Most recent, anonymized client log file of the NetBird client.
netbird.err: Most recent, anonymized stderr log file of the NetBird client.
netbird.out: Most recent, anonymized stdout log file of the NetBird client.
routes.txt: Anonymized system routes, if --system-info flag was provided.
interfaces.txt: Anonymized network interface information, if --system-info flag was provided.
iptables.txt: Anonymized iptables rules with packet counters, if --system-info flag was provided.
nftables.txt: Anonymized nftables rules with packet counters, if --system-info flag was provided.
config.txt: Anonymized configuration information of the NetBird client.
network_map.json: Anonymized network map containing peer configurations, routes, DNS settings, and firewall rules.
state.json: Anonymized client state dump containing netbird states.
mutex.prof: Mutex profiling information.
goroutine.prof: Goroutine profiling information.
block.prof: Block profiling information.
heap.prof: Heap profiling information (snapshot of memory allocations).


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

Network Map
The network_map.json file contains the following anonymized information:
- Peer configurations (addresses, FQDNs, DNS settings)
- Remote and offline peer information (allowed IPs, FQDNs)
- Routes (network ranges, associated domains)
- DNS configuration (nameservers, domains, custom zones)
- Firewall rules (peer IPs, source/destination ranges)

SSH keys in the network map are replaced with a placeholder value. All IP addresses and domains in the network map follow the same anonymization rules as described above.

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

Routes
For anonymized routes, the IP addresses are replaced as described above. The prefix length remains unchanged. Note that for prefixes, the anonymized IP might not be a network address, but the prefix length is still correct.

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
`

const (
	clientLogFile = "client.log"
	errorLogFile  = "netbird.err"
	stdoutLogFile = "netbird.out"

	darwinErrorLogPath  = "/var/log/netbird.out.log"
	darwinStdoutLogPath = "/var/log/netbird.err.log"
)

// DebugBundle creates a debug bundle and returns the location.
func (s *Server) DebugBundle(_ context.Context, req *proto.DebugBundleRequest) (resp *proto.DebugBundleResponse, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	bundlePath, err := os.CreateTemp("", "netbird.debug.*.zip")
	if err != nil {
		return nil, fmt.Errorf("create zip file: %w", err)
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

	if err := s.createArchive(bundlePath, req); err != nil {
		return nil, err
	}

	return &proto.DebugBundleResponse{Path: bundlePath.Name()}, nil
}

func (s *Server) createArchive(bundlePath *os.File, req *proto.DebugBundleRequest) error {
	archive := zip.NewWriter(bundlePath)
	if err := s.addReadme(req, archive); err != nil {
		return fmt.Errorf("add readme: %w", err)
	}

	if err := s.addStatus(req, archive); err != nil {
		return fmt.Errorf("add status: %w", err)
	}

	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
	status := s.statusRecorder.GetFullStatus()
	seedFromStatus(anonymizer, &status)

	if err := s.addConfig(req, anonymizer, archive); err != nil {
		log.Errorf("Failed to add config to debug bundle: %v", err)
	}

	if req.GetSystemInfo() {
		s.addSystemInfo(req, anonymizer, archive)
	}

	if err := s.addProf(req, anonymizer, archive); err != nil {
		log.Errorf("Failed to add goroutines rules to debug bundle: %v", err)
	}

	if err := s.addNetworkMap(req, anonymizer, archive); err != nil {
		return fmt.Errorf("add network map: %w", err)
	}

	if err := s.addStateFile(req, anonymizer, archive); err != nil {
		log.Errorf("Failed to add state file to debug bundle: %v", err)
	}

	if err := s.addCorruptedStateFiles(archive); err != nil {
		log.Errorf("Failed to add corrupted state files to debug bundle: %v", err)
	}

	if s.logFile != "console" {
		if err := s.addLogfile(req, anonymizer, archive); err != nil {
			return fmt.Errorf("add log file: %w", err)
		}
	}

	if err := archive.Close(); err != nil {
		return fmt.Errorf("close archive writer: %w", err)
	}
	return nil
}

func (s *Server) addSystemInfo(req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) {
	if err := s.addRoutes(req, anonymizer, archive); err != nil {
		log.Errorf("Failed to add routes to debug bundle: %v", err)
	}

	if err := s.addInterfaces(req, anonymizer, archive); err != nil {
		log.Errorf("Failed to add interfaces to debug bundle: %v", err)
	}

	if err := s.addFirewallRules(req, anonymizer, archive); err != nil {
		log.Errorf("Failed to add firewall rules to debug bundle: %v", err)
	}
}

func (s *Server) addReadme(req *proto.DebugBundleRequest, archive *zip.Writer) error {
	readmeReader := strings.NewReader(readmeContent)
	if err := addFileToZip(archive, readmeReader, "README.txt"); err != nil {
		return fmt.Errorf("add README file to zip: %w", err)
	}
	return nil
}

func (s *Server) addStatus(req *proto.DebugBundleRequest, archive *zip.Writer) error {
	if status := req.GetStatus(); status != "" {
		statusReader := strings.NewReader(status)
		if err := addFileToZip(archive, statusReader, "status.txt"); err != nil {
			return fmt.Errorf("add status file to zip: %w", err)
		}
	}
	return nil
}

func (s *Server) addConfig(req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) error {
	var configContent strings.Builder
	s.addCommonConfigFields(&configContent)

	if req.GetAnonymize() {
		if s.config.ManagementURL != nil {
			configContent.WriteString(fmt.Sprintf("ManagementURL: %s\n", anonymizer.AnonymizeURI(s.config.ManagementURL.String())))
		}
		if s.config.AdminURL != nil {
			configContent.WriteString(fmt.Sprintf("AdminURL: %s\n", anonymizer.AnonymizeURI(s.config.AdminURL.String())))
		}
		configContent.WriteString(fmt.Sprintf("NATExternalIPs: %v\n", anonymizeNATExternalIPs(s.config.NATExternalIPs, anonymizer)))
		if s.config.CustomDNSAddress != "" {
			configContent.WriteString(fmt.Sprintf("CustomDNSAddress: %s\n", anonymizer.AnonymizeString(s.config.CustomDNSAddress)))
		}
	} else {
		if s.config.ManagementURL != nil {
			configContent.WriteString(fmt.Sprintf("ManagementURL: %s\n", s.config.ManagementURL.String()))
		}
		if s.config.AdminURL != nil {
			configContent.WriteString(fmt.Sprintf("AdminURL: %s\n", s.config.AdminURL.String()))
		}
		configContent.WriteString(fmt.Sprintf("NATExternalIPs: %v\n", s.config.NATExternalIPs))
		if s.config.CustomDNSAddress != "" {
			configContent.WriteString(fmt.Sprintf("CustomDNSAddress: %s\n", s.config.CustomDNSAddress))
		}
	}

	// Add config content to zip file
	configReader := strings.NewReader(configContent.String())
	if err := addFileToZip(archive, configReader, "config.txt"); err != nil {
		return fmt.Errorf("add config file to zip: %w", err)
	}

	return nil
}

func (s *Server) addCommonConfigFields(configContent *strings.Builder) {
	configContent.WriteString("NetBird Client Configuration:\n\n")

	// Add non-sensitive fields
	configContent.WriteString(fmt.Sprintf("WgIface: %s\n", s.config.WgIface))
	configContent.WriteString(fmt.Sprintf("WgPort: %d\n", s.config.WgPort))
	if s.config.NetworkMonitor != nil {
		configContent.WriteString(fmt.Sprintf("NetworkMonitor: %v\n", *s.config.NetworkMonitor))
	}
	configContent.WriteString(fmt.Sprintf("IFaceBlackList: %v\n", s.config.IFaceBlackList))
	configContent.WriteString(fmt.Sprintf("DisableIPv6Discovery: %v\n", s.config.DisableIPv6Discovery))
	configContent.WriteString(fmt.Sprintf("RosenpassEnabled: %v\n", s.config.RosenpassEnabled))
	configContent.WriteString(fmt.Sprintf("RosenpassPermissive: %v\n", s.config.RosenpassPermissive))
	if s.config.ServerSSHAllowed != nil {
		configContent.WriteString(fmt.Sprintf("ServerSSHAllowed: %v\n", *s.config.ServerSSHAllowed))
	}
	configContent.WriteString(fmt.Sprintf("DisableAutoConnect: %v\n", s.config.DisableAutoConnect))
	configContent.WriteString(fmt.Sprintf("DNSRouteInterval: %s\n", s.config.DNSRouteInterval))

	configContent.WriteString(fmt.Sprintf("DisableClientRoutes: %v\n", s.config.DisableClientRoutes))
	configContent.WriteString(fmt.Sprintf("DisableServerRoutes: %v\n", s.config.DisableServerRoutes))
	configContent.WriteString(fmt.Sprintf("DisableDNS: %v\n", s.config.DisableDNS))
	configContent.WriteString(fmt.Sprintf("DisableFirewall: %v\n", s.config.DisableFirewall))

	configContent.WriteString(fmt.Sprintf("BlockLANAccess: %v\n", s.config.BlockLANAccess))
}

func (s *Server) addProf(req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) error {
	runtime.SetBlockProfileRate(1)
	_ = runtime.SetMutexProfileFraction(1)
	defer runtime.SetBlockProfileRate(0)
	defer runtime.SetMutexProfileFraction(0)

	time.Sleep(5 * time.Second)

	for _, profile := range []string{"goroutine", "block", "mutex", "heap"} {
		var buff []byte
		myBuff := bytes.NewBuffer(buff)
		err := pprof.Lookup(profile).WriteTo(myBuff, 0)
		if err != nil {
			return fmt.Errorf("write %s profile: %w", profile, err)
		}

		if err := addFileToZip(archive, myBuff, profile+".prof"); err != nil {
			return fmt.Errorf("add %s file to zip: %w", profile, err)
		}
	}
	return nil
}

func (s *Server) addRoutes(req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) error {
	routes, err := systemops.GetRoutesFromTable()
	if err != nil {
		return fmt.Errorf("get routes: %w", err)
	}

	// TODO: get routes including nexthop
	routesContent := formatRoutes(routes, req.GetAnonymize(), anonymizer)
	routesReader := strings.NewReader(routesContent)
	if err := addFileToZip(archive, routesReader, "routes.txt"); err != nil {
		return fmt.Errorf("add routes file to zip: %w", err)
	}
	return nil
}

func (s *Server) addInterfaces(req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("get interfaces: %w", err)
	}

	interfacesContent := formatInterfaces(interfaces, req.GetAnonymize(), anonymizer)
	interfacesReader := strings.NewReader(interfacesContent)
	if err := addFileToZip(archive, interfacesReader, "interfaces.txt"); err != nil {
		return fmt.Errorf("add interfaces file to zip: %w", err)
	}

	return nil
}

func (s *Server) addNetworkMap(req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) error {
	networkMap, err := s.getLatestNetworkMap()
	if err != nil {
		// Skip if network map is not available, but log it
		log.Debugf("skipping empty network map in debug bundle: %v", err)
		return nil
	}

	if req.GetAnonymize() {
		if err := anonymizeNetworkMap(networkMap, anonymizer); err != nil {
			return fmt.Errorf("anonymize network map: %w", err)
		}
	}

	options := protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
		Indent:          "  ",
		AllowPartial:    true,
	}

	jsonBytes, err := options.Marshal(networkMap)
	if err != nil {
		return fmt.Errorf("generate json: %w", err)
	}

	if err := addFileToZip(archive, bytes.NewReader(jsonBytes), "network_map.json"); err != nil {
		return fmt.Errorf("add network map to zip: %w", err)
	}

	return nil
}

func (s *Server) addStateFile(req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) error {
	path := statemanager.GetDefaultStatePath()
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read state file: %w", err)
	}

	if req.GetAnonymize() {
		var rawStates map[string]json.RawMessage
		if err := json.Unmarshal(data, &rawStates); err != nil {
			return fmt.Errorf("unmarshal states: %w", err)
		}

		if err := anonymizeStateFile(&rawStates, anonymizer); err != nil {
			return fmt.Errorf("anonymize state file: %w", err)
		}

		bs, err := json.MarshalIndent(rawStates, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal states: %w", err)
		}
		data = bs
	}

	if err := addFileToZip(archive, bytes.NewReader(data), "state.json"); err != nil {
		return fmt.Errorf("add state file to zip: %w", err)
	}

	return nil
}

func (s *Server) addCorruptedStateFiles(archive *zip.Writer) error {
	pattern := statemanager.GetDefaultStatePath()
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
		if err := addFileToZip(archive, bytes.NewReader(data), "corrupted_states/"+fileName); err != nil {
			log.Warnf("Failed to add corrupted state file %s to zip: %v", fileName, err)
			continue
		}

		log.Debugf("Added corrupted state file to debug bundle: %s", fileName)
	}

	return nil
}

func (s *Server) addLogfile(req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) error {
	logDir := filepath.Dir(s.logFile)

	if err := s.addSingleLogfile(s.logFile, clientLogFile, req, anonymizer, archive); err != nil {
		return fmt.Errorf("add client log file to zip: %w", err)
	}

	stdErrLogPath := filepath.Join(logDir, errorLogFile)
	stdoutLogPath := filepath.Join(logDir, stdoutLogFile)
	if runtime.GOOS == "darwin" {
		stdErrLogPath = darwinErrorLogPath
		stdoutLogPath = darwinStdoutLogPath
	}

	if err := s.addSingleLogfile(stdErrLogPath, errorLogFile, req, anonymizer, archive); err != nil {
		log.Warnf("Failed to add %s to zip: %v", errorLogFile, err)
	}

	if err := s.addSingleLogfile(stdoutLogPath, stdoutLogFile, req, anonymizer, archive); err != nil {
		log.Warnf("Failed to add %s to zip: %v", stdoutLogFile, err)
	}

	return nil
}

// addSingleLogfile adds a single log file to the archive
func (s *Server) addSingleLogfile(logPath, targetName string, req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) error {
	logFile, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", targetName, err)
	}
	defer func() {
		if err := logFile.Close(); err != nil {
			log.Errorf("Failed to close log file %s: %v", targetName, err)
		}
	}()

	var logReader io.Reader
	if req.GetAnonymize() {
		var writer *io.PipeWriter
		logReader, writer = io.Pipe()

		go anonymizeLog(logFile, writer, anonymizer)
	} else {
		logReader = logFile
	}

	if err := addFileToZip(archive, logReader, targetName); err != nil {
		return fmt.Errorf("add %s to zip: %w", targetName, err)
	}

	return nil
}

// getLatestNetworkMap returns the latest network map from the engine if network map persistence is enabled
func (s *Server) getLatestNetworkMap() (*mgmProto.NetworkMap, error) {
	if s.connectClient == nil {
		return nil, errors.New("connect client is not initialized")
	}

	engine := s.connectClient.Engine()
	if engine == nil {
		return nil, errors.New("engine is not initialized")
	}

	networkMap, err := engine.GetLatestNetworkMap()
	if err != nil {
		return nil, fmt.Errorf("get latest network map: %w", err)
	}

	if networkMap == nil {
		return nil, errors.New("network map is not available")
	}

	return networkMap, nil
}

// GetLogLevel gets the current logging level for the server.
func (s *Server) GetLogLevel(_ context.Context, _ *proto.GetLogLevelRequest) (*proto.GetLogLevelResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	level := ParseLogLevel(log.GetLevel().String())
	return &proto.GetLogLevelResponse{Level: level}, nil
}

// SetLogLevel sets the logging level for the server.
func (s *Server) SetLogLevel(_ context.Context, req *proto.SetLogLevelRequest) (*proto.SetLogLevelResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	level, err := log.ParseLevel(req.Level.String())
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	log.SetLevel(level)

	if s.connectClient == nil {
		return nil, fmt.Errorf("connect client not initialized")
	}
	engine := s.connectClient.Engine()
	if engine == nil {
		return nil, fmt.Errorf("engine not initialized")
	}

	fwManager := engine.GetFirewallManager()
	if fwManager == nil {
		return nil, fmt.Errorf("firewall manager not initialized")
	}

	fwManager.SetLogLevel(level)

	log.Infof("Log level set to %s", level.String())

	return &proto.SetLogLevelResponse{}, nil
}

// SetNetworkMapPersistence sets the network map persistence for the server.
func (s *Server) SetNetworkMapPersistence(_ context.Context, req *proto.SetNetworkMapPersistenceRequest) (*proto.SetNetworkMapPersistenceResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	enabled := req.GetEnabled()
	s.persistNetworkMap = enabled
	if s.connectClient != nil {
		s.connectClient.SetNetworkMapPersistence(enabled)
	}

	return &proto.SetNetworkMapPersistenceResponse{}, nil
}

func addFileToZip(archive *zip.Writer, reader io.Reader, filename string) error {
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
			log.Tracef("Failed to get file stat for %s: %v", filename, err)
		} else {
			header.Modified = stat.ModTime()
		}
	}

	writer, err := archive.CreateHeader(header)
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

	for _, peer := range status.Peers {
		a.AnonymizeDomain(peer.FQDN)
		for route := range peer.GetRoutes() {
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

func formatRoutes(routes []netip.Prefix, anonymize bool, anonymizer *anonymize.Anonymizer) string {
	var ipv4Routes, ipv6Routes []netip.Prefix

	// Separate IPv4 and IPv6 routes
	for _, route := range routes {
		if route.Addr().Is4() {
			ipv4Routes = append(ipv4Routes, route)
		} else {
			ipv6Routes = append(ipv6Routes, route)
		}
	}

	// Sort IPv4 and IPv6 routes separately
	sort.Slice(ipv4Routes, func(i, j int) bool {
		return ipv4Routes[i].Bits() > ipv4Routes[j].Bits()
	})
	sort.Slice(ipv6Routes, func(i, j int) bool {
		return ipv6Routes[i].Bits() > ipv6Routes[j].Bits()
	})

	var builder strings.Builder

	// Format IPv4 routes
	builder.WriteString("IPv4 Routes:\n")
	for _, route := range ipv4Routes {
		formatRoute(&builder, route, anonymize, anonymizer)
	}

	// Format IPv6 routes
	builder.WriteString("\nIPv6 Routes:\n")
	for _, route := range ipv6Routes {
		formatRoute(&builder, route, anonymize, anonymizer)
	}

	return builder.String()
}

func formatRoute(builder *strings.Builder, route netip.Prefix, anonymize bool, anonymizer *anonymize.Anonymizer) {
	if anonymize {
		anonymizedIP := anonymizer.AnonymizeIP(route.Addr())
		builder.WriteString(fmt.Sprintf("%s/%d\n", anonymizedIP, route.Bits()))
	} else {
		builder.WriteString(fmt.Sprintf("%s\n", route))
	}
}

func formatInterfaces(interfaces []net.Interface, anonymize bool, anonymizer *anonymize.Anonymizer) string {
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Name < interfaces[j].Name
	})

	var builder strings.Builder
	builder.WriteString("Network Interfaces:\n")

	for _, iface := range interfaces {
		builder.WriteString(fmt.Sprintf("\nInterface: %s\n", iface.Name))
		builder.WriteString(fmt.Sprintf("  Index: %d\n", iface.Index))
		builder.WriteString(fmt.Sprintf("  MTU: %d\n", iface.MTU))
		builder.WriteString(fmt.Sprintf("  Flags: %v\n", iface.Flags))

		addrs, err := iface.Addrs()
		if err != nil {
			builder.WriteString(fmt.Sprintf("  Addresses: Error retrieving addresses: %v\n", err))
		} else {
			builder.WriteString("  Addresses:\n")
			for _, addr := range addrs {
				prefix, err := netip.ParsePrefix(addr.String())
				if err != nil {
					builder.WriteString(fmt.Sprintf("    Error parsing address: %v\n", err))
					continue
				}
				ip := prefix.Addr()
				if anonymize {
					ip = anonymizer.AnonymizeIP(ip)
				}
				builder.WriteString(fmt.Sprintf("    %s/%d\n", ip, prefix.Bits()))
			}
		}
	}

	return builder.String()
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
			writer.CloseWithError(fmt.Errorf("anonymize write: %w", err))
			return
		}
	}
	if err := scanner.Err(); err != nil {
		writer.CloseWithError(fmt.Errorf("anonymize scan: %w", err))
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

	for _, peer := range networkMap.RemotePeers {
		anonymizeRemotePeer(peer, anonymizer)
	}

	for _, peer := range networkMap.OfflinePeers {
		anonymizeRemotePeer(peer, anonymizer)
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

func anonymizePeerConfig(config *mgmProto.PeerConfig, anonymizer *anonymize.Anonymizer) {
	if config == nil {
		return
	}

	if addr, err := netip.ParseAddr(config.Address); err == nil {
		config.Address = anonymizer.AnonymizeIP(addr).String()
	}

	if config.SshConfig != nil && len(config.SshConfig.SshPubKey) > 0 {
		config.SshConfig.SshPubKey = []byte("ssh-placeholder-key")
	}

	config.Dns = anonymizer.AnonymizeString(config.Dns)
	config.Fqdn = anonymizer.AnonymizeDomain(config.Fqdn)
}

func anonymizeRemotePeer(peer *mgmProto.RemotePeerConfig, anonymizer *anonymize.Anonymizer) {
	if peer == nil {
		return
	}

	for i, ip := range peer.AllowedIps {
		// Try to parse as prefix first (CIDR)
		if prefix, err := netip.ParsePrefix(ip); err == nil {
			anonIP := anonymizer.AnonymizeIP(prefix.Addr())
			peer.AllowedIps[i] = fmt.Sprintf("%s/%d", anonIP, prefix.Bits())
		} else if addr, err := netip.ParseAddr(ip); err == nil {
			peer.AllowedIps[i] = anonymizer.AnonymizeIP(addr).String()
		}
	}

	peer.Fqdn = anonymizer.AnonymizeDomain(peer.Fqdn)

	if peer.SshConfig != nil && len(peer.SshConfig.SshPubKey) > 0 {
		peer.SshConfig.SshPubKey = []byte("ssh-placeholder-key")
	}
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

	anonymizeNameServerGroups(config.NameServerGroups, anonymizer)
	anonymizeCustomZones(config.CustomZones, anonymizer)
}

func anonymizeNameServerGroups(groups []*mgmProto.NameServerGroup, anonymizer *anonymize.Anonymizer) {
	for _, group := range groups {
		anonymizeServers(group.NameServers, anonymizer)
		anonymizeDomains(group.Domains, anonymizer)
	}
}

func anonymizeServers(servers []*mgmProto.NameServer, anonymizer *anonymize.Anonymizer) {
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
	case 1, 28: // A or AAAA record
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
