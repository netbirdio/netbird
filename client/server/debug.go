//go:build !android && !ios

package server

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
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
		if err := bundlePath.Close(); err != nil {
			log.Errorf("failed to close zip file: %v", err)
		}

		if err != nil {
			if err2 := os.Remove(bundlePath.Name()); err2 != nil {
				log.Errorf("Failed to remove zip file: %v", err2)
			}
		}
	}()

	archive := zip.NewWriter(bundlePath)
	defer func() {
		if err := archive.Close(); err != nil {
			log.Errorf("failed to close archive writer: %v", err)
		}
	}()

	// Create anonymizer
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
	status := s.statusRecorder.GetFullStatus()
	seedFromStatus(anonymizer, &status)

	// Add status file
	if status := req.GetStatus(); status != "" {
		filename := "status.txt"
		if req.GetAnonymize() {
			filename = "status.anon.txt"
		}
		statusReader := strings.NewReader(status)
		if err := addFileToZip(archive, statusReader, filename); err != nil {
			return nil, fmt.Errorf("add status file to zip: %w", err)
		}
	}

	// Add log file
	logFile, err := os.Open(s.logFile)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	defer func() {
		if err := logFile.Close(); err != nil {
			log.Errorf("failed to close original log file: %v", err)
		}
	}()

	filename := "client.log.txt"
	var logReader io.Reader
	errChan := make(chan error, 1)
	if req.GetAnonymize() {
		filename = "client.anon.log.txt"
		var writer io.WriteCloser
		logReader, writer = io.Pipe()

		go s.anonymize(logFile, writer, errChan, anonymizer)
	} else {
		logReader = logFile
	}
	if err := addFileToZip(archive, logReader, filename); err != nil {
		return nil, fmt.Errorf("add log file to zip: %w", err)
	}

	// Add routes output
	routes, err := systemops.GetRoutesFromTable()
	if err != nil {
		log.Errorf("Failed to get routes: %v", err)
	} else {
		// TODO: get routes including nexthop
		routesContent := formatRoutes(routes, req.GetAnonymize(), anonymizer)
		routesReader := strings.NewReader(routesContent)
		if err := addFileToZip(archive, routesReader, "routes.txt"); err != nil {
			return nil, fmt.Errorf("add routes file to zip: %w", err)
		}
	}

	select {
	case err := <-errChan:
		if err != nil {
			return nil, err
		}
	default:
	}

	return &proto.DebugBundleResponse{Path: bundlePath.Name()}, nil
}

func (s *Server) anonymize(reader io.Reader, writer io.WriteCloser, errChan chan<- error, anonymizer *anonymize.Anonymizer) {
	scanner := bufio.NewScanner(reader)

	defer func() {
		if err := writer.Close(); err != nil {
			log.Errorf("Failed to close writer: %v", err)
		}
	}()
	for scanner.Scan() {
		line := anonymizer.AnonymizeString(scanner.Text())
		if _, err := writer.Write([]byte(line + "\n")); err != nil {
			errChan <- fmt.Errorf("write line to writer: %w", err)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		errChan <- fmt.Errorf("read line from scanner: %w", err)
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
		if relay.URI != nil {
			a.AnonymizeURI(relay.URI.String())
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
	builder.WriteString("\nIPv4 Routes:\n")
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
