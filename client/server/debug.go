package server

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal/peer"
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

		go s.anonymize(logFile, writer, errChan)
	} else {
		logReader = logFile
	}
	if err := addFileToZip(archive, logReader, filename); err != nil {
		return nil, fmt.Errorf("add log file to zip: %w", err)
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

func (s *Server) anonymize(reader io.Reader, writer io.WriteCloser, errChan chan<- error) {
	scanner := bufio.NewScanner(reader)
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	status := s.statusRecorder.GetFullStatus()
	seedFromStatus(anonymizer, &status)

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
		Name:   filename,
		Method: zip.Deflate,
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
