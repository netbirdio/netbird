package server

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util/anonymize"
)

// DebugBundle creates a debug bundle and returns the location.
func (s *Server) DebugBundle(ctx context.Context, req *proto.DebugBundleRequest) (resp *proto.DebugBundleResponse, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.logFile == "console" {
		return nil, fmt.Errorf("log file is set to console, cannot create debug bundle")
	}
	originalLogFile, err := os.Open(s.logFile)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	defer func() {
		if err := originalLogFile.Close(); err != nil {
			log.Errorf("failed to close original log file: %v", err)
		}
	}()

	newLogFile, err := os.CreateTemp("", "client.*.log")
	if err != nil {
		return nil, fmt.Errorf("create anonymized log file: %w", err)
	}
	defer func() {
		if err := newLogFile.Close(); err != nil {
			log.Errorf("failed to close anonymized log file: %v", err)
		}

		if err != nil {
			if err2 := os.Remove(newLogFile.Name()); err2 != nil {
				log.Errorf("Failed to remove temp dir: %v", err)
			}
		}
	}()

	scanner := bufio.NewScanner(originalLogFile)
	writer := bufio.NewWriter(newLogFile)

	if req.GetAnonymize() {
		anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

		status := s.statusRecorder.GetFullStatus()
		seedFromStatus(anonymizer, &status)

		for scanner.Scan() {
			line := anonymizer.AnonymizeString(scanner.Text())
			if _, err := writer.WriteString(line + "\n"); err != nil {
				return nil, fmt.Errorf("write: %w", err)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}

		if err := writer.Flush(); err != nil {
			return nil, fmt.Errorf("flush: %w", err)
		}
	} else {
		_, err = io.Copy(writer, originalLogFile)
		if err != nil {
			return nil, fmt.Errorf("copy log file: %w", err)
		}
	}

	bundlePath, err := zipFile(newLogFile.Name())
	if err != nil {
		return nil, fmt.Errorf("zip log file: %w", err)
	}

	return &proto.DebugBundleResponse{Path: bundlePath}, nil
}

func zipFile(source string) (path string, err error) {
	zipfile, err := os.CreateTemp("", "debug.*.zip")
	if err != nil {
		return "", fmt.Errorf("create zip file: %w", err)
	}
	defer func() {
		if err := zipfile.Close(); err != nil {
			log.Errorf("failed to close zip file: %v", err)
		}

		if err != nil {
			if err2 := os.Remove(zipfile.Name()); err2 != nil {
				log.Errorf("Failed to remove zip file: %v", err)
			}
		}
	}()

	archive := zip.NewWriter(zipfile)
	defer func() {
		if err := archive.Close(); err != nil {
			log.Errorf("failed to close archive writer: %v", err)
		}
	}()

	fileToZip, err := os.Open(source)
	if err != nil {
		return "", fmt.Errorf("open file to zip: %w", err)
	}
	defer func() {
		if err := fileToZip.Close(); err != nil {
			log.Errorf("failed to close file to zip: %v", err)
		}
	}()

	info, err := fileToZip.Stat()
	if err != nil {
		return "", fmt.Errorf("stat file to zip: %w", err)
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return "", fmt.Errorf("get file info header: %w", err)
	}

	header.Name = filepath.Base(source)
	header.Method = zip.Deflate

	writer, err := archive.CreateHeader(header)
	if err != nil {
		return "", fmt.Errorf("create zip file header: %w", err)
	}

	if _, err := io.Copy(writer, fileToZip); err != nil {
		return "", fmt.Errorf("write file to zip: %w", err)
	}

	return zipfile.Name(), nil
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
