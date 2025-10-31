//go:build darwin && !ios

package debug

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// addDNSInfo collects and adds DNS configuration information to the archive
func (g *BundleGenerator) addDNSInfo() error {
	if err := g.addResolvConf(); err != nil {
		log.Errorf("failed to add resolv.conf: %v", err)
	}

	if err := g.addScutilDNS(); err != nil {
		log.Errorf("failed to add scutil DNS output: %v", err)
	}

	return nil
}

func (g *BundleGenerator) addScutilDNS() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "scutil", "--dns")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("execute scutil --dns: %w", err)
	}

	if len(bytes.TrimSpace(output)) == 0 {
		return fmt.Errorf("no scutil DNS output")
	}

	content := string(output)
	if g.anonymize {
		content = g.anonymizer.AnonymizeString(content)
	}

	if err := g.addFileToZip(strings.NewReader(content), "scutil_dns.txt"); err != nil {
		return fmt.Errorf("add scutil DNS output to zip: %w", err)
	}

	return nil
}
