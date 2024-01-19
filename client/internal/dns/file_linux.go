//go:build !android

package dns

import (
	"bytes"
	"fmt"
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
				return fmt.Errorf("unable to configure DNS for this peer using file manager without a Primary nameserver group. Restoring the original file return err: %s", err)
			}
		}
		return fmt.Errorf("unable to configure DNS for this peer using file manager without a nameserver group with all domains configured")
	}

	if !backupFileExist {
		err = f.backup()
		if err != nil {
			return fmt.Errorf("unable to backup the resolv.conf file")
		}
	}

	searchDomainList := searchDomains(config)

	originalSearchDomains, nameServers, others, err := parseResolvConf(fileDefaultResolvConfBackupLocation)
	if err != nil {
		log.Error(err)
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
		return fmt.Errorf("got an creating resolver file %s. Error: %s", defaultResolvConfPath, err)
	}

	log.Infof("created a NetBird managed %s file with your DNS settings. Added %d search domains. Search list: %s", defaultResolvConfPath, len(searchDomainList), searchDomainList)
	return nil
}

func (f *fileConfigurator) restoreHostDNS() error {
	return f.restore()
}

func (f *fileConfigurator) backup() error {
	stats, err := os.Stat(defaultResolvConfPath)
	if err != nil {
		return fmt.Errorf("got an error while checking stats for %s file. Error: %s", defaultResolvConfPath, err)
	}

	f.originalPerms = stats.Mode()

	err = copyFile(defaultResolvConfPath, fileDefaultResolvConfBackupLocation)
	if err != nil {
		return fmt.Errorf("got error while backing up the %s file. Error: %s", defaultResolvConfPath, err)
	}
	return nil
}

func (f *fileConfigurator) restore() error {
	err := copyFile(fileDefaultResolvConfBackupLocation, defaultResolvConfPath)
	if err != nil {
		return fmt.Errorf("got error while restoring the %s file from %s. Error: %s", defaultResolvConfPath, fileDefaultResolvConfBackupLocation, err)
	}

	return os.RemoveAll(fileDefaultResolvConfBackupLocation)
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
		return fmt.Errorf("got an error while checking stats for %s file when copying it. Error: %s", src, err)
	}

	bytesRead, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("got an error while reading the file %s file for copy. Error: %s", src, err)
	}

	err = os.WriteFile(dest, bytesRead, stats.Mode())
	if err != nil {
		return fmt.Errorf("got an writing the destination file %s for copy. Error: %s", dest, err)
	}
	return nil
}
