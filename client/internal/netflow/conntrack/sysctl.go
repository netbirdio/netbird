//go:build linux && !android

package conntrack

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// conntrackAcctPath is the sysctl path for conntrack accounting
	conntrackAcctPath = "net.netfilter.nf_conntrack_acct"
)

// EnableAccounting ensures that connection tracking accounting is enabled  in the kernel.
func (c *ConnTrack) EnableAccounting() {
	// haven't restored yet
	if c.sysctlModified {
		return
	}

	modified, err := setSysctl(conntrackAcctPath, 1)
	if err != nil {
		log.Warnf("Failed to enable conntrack accounting: %v", err)
		return
	}
	c.sysctlModified = modified
}

// RestoreAccounting restores the connection tracking accounting setting to its original value.
func (c *ConnTrack) RestoreAccounting() {
	if !c.sysctlModified {
		return
	}

	if _, err := setSysctl(conntrackAcctPath, 0); err != nil {
		log.Warnf("Failed to restore conntrack accounting: %v", err)
		return
	}

	c.sysctlModified = false
}

// setSysctl sets a sysctl configuration and returns whether it was modified.
func setSysctl(key string, desiredValue int) (bool, error) {
	path := fmt.Sprintf("/proc/sys/%s", strings.ReplaceAll(key, ".", "/"))

	currentValue, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read sysctl %s: %w", key, err)
	}

	currentV, err := strconv.Atoi(strings.TrimSpace(string(currentValue)))
	if err != nil && len(currentValue) > 0 {
		return false, fmt.Errorf("convert current value to int: %w", err)
	}

	if currentV == desiredValue {
		return false, nil
	}

	// nolint:gosec
	if err := os.WriteFile(path, []byte(strconv.Itoa(desiredValue)), 0644); err != nil {
		return false, fmt.Errorf("write sysctl %s: %w", key, err)
	}

	log.Debugf("Set sysctl %s from %d to %d", key, currentV, desiredValue)
	return true, nil
}
