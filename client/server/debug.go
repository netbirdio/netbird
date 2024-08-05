//go:build !android && !ios

package server

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/proto"
)

const readmeContent = `Netbird debug bundle
This debug bundle contains the following files:

status.txt: Anonymized status information of the NetBird client.
client.log: Most recent, anonymized log file of the NetBird client.
routes.txt: Anonymized system routes, if --system-info flag was provided.
interfaces.txt: Anonymized network interface information, if --system-info flag was provided.
config.txt: Anonymized configuration information of the NetBird client.


Anonymization Process
The files in this bundle have been anonymized to protect sensitive information. Here's how the anonymization was applied:

IP Addresses

IPv4 addresses are replaced with addresses starting from 192.51.100.0
IPv6 addresses are replaced with addresses starting from 100::

IP addresses from non public ranges and well known addresses are not anonymized (e.g. 8.8.8.8, 100.64.0.0/10, addresses starting with 192.168., 172.16., 10., etc.).
Reoccuring IP addresses are replaced with the same anonymized address.

Note: The anonymized IP addresses in the status file do not match those in the log and routes files. However, the anonymized IP addresses are consistent within the status file and across the routes and log files.

Domains
All domain names (except for the netbird domains) are replaced with randomly generated strings ending in ".domain". Anonymized domains are consistent across all files in the bundle.
Reoccuring domain names are replaced with the same anonymized domain.

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
`

// DebugBundle creates a debug bundle and returns the location.
func (s *Server) DebugBundle(_ context.Context, req *proto.DebugBundleRequest) (resp *proto.DebugBundleResponse, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.logFile == "console" {
		return nil, fmt.Errorf("log file is set to console, cannot create debug bundle")
	}

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
		return fmt.Errorf("add config: %w", err)
	}

	if req.GetSystemInfo() {
		if err := s.addRoutes(req, anonymizer, archive); err != nil {
			return fmt.Errorf("add routes: %w", err)
		}

		if err := s.addInterfaces(req, anonymizer, archive); err != nil {
			return fmt.Errorf("add interfaces: %w", err)
		}
	}

	if err := s.addLogfile(req, anonymizer, archive); err != nil {
		return fmt.Errorf("add log file: %w", err)
	}

	if err := archive.Close(); err != nil {
		return fmt.Errorf("close archive writer: %w", err)
	}
	return nil
}

func (s *Server) addReadme(req *proto.DebugBundleRequest, archive *zip.Writer) error {
	if req.GetAnonymize() {
		readmeReader := strings.NewReader(readmeContent)
		if err := addFileToZip(archive, readmeReader, "README.txt"); err != nil {
			return fmt.Errorf("add README file to zip: %w", err)
		}
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
}

func (s *Server) addRoutes(req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) error {
	if routes, err := systemops.GetRoutesFromTable(); err != nil {
		log.Errorf("Failed to get routes: %v", err)
	} else {
		// TODO: get routes including nexthop
		routesContent := formatRoutes(routes, req.GetAnonymize(), anonymizer)
		routesReader := strings.NewReader(routesContent)
		if err := addFileToZip(archive, routesReader, "routes.txt"); err != nil {
			return fmt.Errorf("add routes file to zip: %w", err)
		}
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

func (s *Server) addLogfile(req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) (err error) {
	logFile, err := os.Open(s.logFile)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer func() {
		if err := logFile.Close(); err != nil {
			log.Errorf("Failed to close original log file: %v", err)
		}
	}()

	var logReader io.Reader
	if req.GetAnonymize() {
		var writer *io.PipeWriter
		logReader, writer = io.Pipe()

		go s.anonymize(logFile, writer, anonymizer)
	} else {
		logReader = logFile
	}
	if err := addFileToZip(archive, logReader, "client.log"); err != nil {
		return fmt.Errorf("add log file to zip: %w", err)
	}

	return nil
}

func (s *Server) anonymize(reader io.Reader, writer *io.PipeWriter, anonymizer *anonymize.Anonymizer) {
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

// GetLogLevel gets the current logging level for the server.
func (s *Server) GetLogLevel(_ context.Context, _ *proto.GetLogLevelRequest) (*proto.GetLogLevelResponse, error) {
	level := ParseLogLevel(log.GetLevel().String())
	return &proto.GetLogLevelResponse{Level: level}, nil
}

// SetLogLevel sets the logging level for the server.
func (s *Server) SetLogLevel(_ context.Context, req *proto.SetLogLevelRequest) (*proto.SetLogLevelResponse, error) {
	level, err := log.ParseLevel(req.Level.String())
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	log.SetLevel(level)
	log.Infof("Log level set to %s", level.String())
	return &proto.SetLogLevelResponse{}, nil
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
