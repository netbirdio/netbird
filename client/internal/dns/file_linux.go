//go:build !android

package dns

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	fileGeneratedResolvConfContentHeader         = "# Generated by NetBird"
	fileGeneratedResolvConfContentHeaderNextLine = fileGeneratedResolvConfContentHeader + `
# If needed you can restore the original file by copying back ` + fileDefaultResolvConfBackupLocation + "\n\n"

	fileDefaultResolvConfBackupLocation = defaultResolvConfPath + ".original.netbird"

	fileMaxLineCharsLimit        = 256
	fileMaxNumberOfSearchDomains = 6
)

type fileConfigurator struct {
	originalPerms os.FileMode
}

func newFileConfigurator() (hostManager, error) {
	return &fileConfigurator{}, nil
}

func (f *fileConfigurator) supportCustomPort() bool {
	return false
}

func (f *fileConfigurator) applyDNSConfig(config HostDNSConfig) error {
	backupFileExist := false
	_, err := os.Stat(fileDefaultResolvConfBackupLocation)
	if err == nil {
		backupFileExist = true
	}

	if !config.RouteAll {
		if backupFileExist {
			err = f.restore()
			if err != nil {
				return fmt.Errorf("unable to configure DNS for this peer using file manager without a Primary nameserver group. Restoring the original file return err: %w", err)
			}
		}
		return fmt.Errorf("unable to configure DNS for this peer using file manager without a nameserver group with all domains configured")
	}

	if !backupFileExist {
		err = f.backup()
		if err != nil {
			return fmt.Errorf("unable to backup the resolv.conf file: %w", err)
		}
	}

	searchDomainList := searchDomains(config)

	originalSearchDomains, nameServers, others, err := originalDNSConfigs(fileDefaultResolvConfBackupLocation)
	if err != nil {
		log.Errorf("could not read original search domains from %s: %s", fileDefaultResolvConfBackupLocation, err)
	}

	searchDomainList = mergeSearchDomains(searchDomainList, originalSearchDomains)

	buf := prepareResolvConfContent(
		searchDomainList,
		append([]string{config.ServerIP}, nameServers...),
		others)

	log.Debugf("creating managed file %s", defaultResolvConfPath)
	err = os.WriteFile(defaultResolvConfPath, buf.Bytes(), f.originalPerms)
	if err != nil {
		restoreErr := f.restore()
		if restoreErr != nil {
			log.Errorf("attempt to restore default file failed with error: %s", err)
		}
		return fmt.Errorf("got an error creating resolver file %s. Error: %w", defaultResolvConfPath, err)
	}

	log.Infof("created a NetBird managed %s file with the DNS settings. Added %d search domains. Search list: %s", defaultResolvConfPath, len(searchDomainList), searchDomainList)

	// create another backup for unclean shutdown detection right after overwriting the original resolv.conf
	if err := createUncleanShutdownIndicator(fileDefaultResolvConfBackupLocation, fileManager); err != nil {
		log.Errorf("failed to create unclean shutdown resolv.conf backup: %s", err)
	}

	return nil
}

func (f *fileConfigurator) restoreHostDNS() error {
	return f.restore()
}

func (f *fileConfigurator) backup() error {
	stats, err := os.Stat(defaultResolvConfPath)
	if err != nil {
		return fmt.Errorf("checking stats for %s file. Error: %w", defaultResolvConfPath, err)
	}

	f.originalPerms = stats.Mode()

	err = copyFile(defaultResolvConfPath, fileDefaultResolvConfBackupLocation)
	if err != nil {
		return fmt.Errorf("backing up %s: %w", defaultResolvConfPath, err)
	}
	return nil
}

func (f *fileConfigurator) restore() error {
	err := copyFile(fileDefaultResolvConfBackupLocation, defaultResolvConfPath)
	if err != nil {
		return fmt.Errorf("restoring %s from %s: %w", defaultResolvConfPath, fileDefaultResolvConfBackupLocation, err)
	}

	if err := removeUncleanShutdownIndicator(); err != nil {
		log.Errorf("failed to remove unclean shutdown resolv.conf backup: %s", err)
	}

	return os.RemoveAll(fileDefaultResolvConfBackupLocation)
}

func (f *fileConfigurator) restoreUncleanShutdownDNS() error {
	if err := copyFile(fileUncleanShutdownResolvConfLocation, defaultResolvConfPath); err != nil {
		return fmt.Errorf("restoring %s from %s: %w", defaultResolvConfPath, fileUncleanShutdownResolvConfLocation, err)
	}

	if err := removeUncleanShutdownIndicator(); err != nil {
		log.Errorf("failed to remove unclean shutdown resolv.conf backup: %s", err)
	}

	return nil
}

func prepareResolvConfContent(searchDomains, nameServers, others []string) bytes.Buffer {
	var buf bytes.Buffer
	buf.WriteString(fileGeneratedResolvConfContentHeaderNextLine)

	for _, cfgLine := range others {
		buf.WriteString(cfgLine)
		buf.WriteString("\n")
	}

	if len(searchDomains) > 0 {
		buf.WriteString("search ")
		buf.WriteString(strings.Join(searchDomains, " "))
		buf.WriteString("\n")
	}

	for _, ns := range nameServers {
		buf.WriteString("nameserver ")
		buf.WriteString(ns)
		buf.WriteString("\n")
	}
	return buf
}

func searchDomains(config HostDNSConfig) []string {
	listOfDomains := make([]string, 0)
	for _, dConf := range config.Domains {
		if dConf.MatchOnly || dConf.Disabled {
			continue
		}

		listOfDomains = append(listOfDomains, dConf.Domain)
	}
	return listOfDomains
}

func originalDNSConfigs(resolvconfFile string) (searchDomains, nameServers, others []string, err error) {
	file, err := os.Open(resolvconfFile)
	if err != nil {
		err = fmt.Errorf("open: %w", err)
		return
	}
	defer func() {
		// not critical, we don't write
		if err := file.Close(); err != nil {
			log.Errorf("close %s: %s", resolvconfFile, err)
		}
	}()

	reader := bufio.NewReader(file)

	for {
		lineBytes, isPrefix, readErr := reader.ReadLine()
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			err = fmt.Errorf("read line: %s", readErr)
			return
		}

		if isPrefix {
			err = fmt.Errorf("resolv.conf line too long")
			return
		}

		line := strings.TrimSpace(string(lineBytes))

		if strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "domain") {
			continue
		}

		if strings.HasPrefix(line, "options") && strings.Contains(line, "rotate") {
			line = strings.ReplaceAll(line, "rotate", "")
			splitLines := strings.Fields(line)
			if len(splitLines) == 1 {
				continue
			}
			line = strings.Join(splitLines, " ")
		}

		if strings.HasPrefix(line, "search") {
			splitLines := strings.Fields(line)
			if len(splitLines) < 2 {
				continue
			}

			searchDomains = splitLines[1:]
			continue
		}

		if strings.HasPrefix(line, "nameserver") {
			splitLines := strings.Fields(line)
			if len(splitLines) != 2 {
				continue
			}
			nameServers = append(nameServers, splitLines[1])
			continue
		}

		others = append(others, line)
	}
	return
}

// merge search Domains lists and cut off the list if it is too long
func mergeSearchDomains(searchDomains []string, originalSearchDomains []string) []string {
	lineSize := len("search")
	searchDomainsList := make([]string, 0, len(searchDomains)+len(originalSearchDomains))

	lineSize = validateAndFillSearchDomains(lineSize, &searchDomainsList, searchDomains)
	_ = validateAndFillSearchDomains(lineSize, &searchDomainsList, originalSearchDomains)

	return searchDomainsList
}

// validateAndFillSearchDomains checks if the search Domains list is not too long and if the line is not too long
// extend s slice with vs elements
// return with the number of characters in the searchDomains line
func validateAndFillSearchDomains(initialLineChars int, s *[]string, vs []string) int {
	for _, sd := range vs {
		tmpCharsNumber := initialLineChars + 1 + len(sd)
		if tmpCharsNumber > fileMaxLineCharsLimit {
			// lets log all skipped Domains
			log.Infof("search list line is larger than %d characters. Skipping append of %s domain", fileMaxLineCharsLimit, sd)
			continue
		}

		initialLineChars = tmpCharsNumber

		if len(*s) >= fileMaxNumberOfSearchDomains {
			// lets log all skipped Domains
			log.Infof("already appended %d domains to search list. Skipping append of %s domain", fileMaxNumberOfSearchDomains, sd)
			continue
		}
		*s = append(*s, sd)
	}
	return initialLineChars
}

func copyFile(src, dest string) error {
	stats, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("checking stats for %s file when copying it. Error: %s", src, err)
	}

	bytesRead, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading the file %s file for copy. Error: %s", src, err)
	}

	err = os.WriteFile(dest, bytesRead, stats.Mode())
	if err != nil {
		return fmt.Errorf("writing the destination file %s for copy. Error: %s", dest, err)
	}
	return nil
}
