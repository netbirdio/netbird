// go:build !android
package sysctl

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/iface"
)

const (
	rpFilterPath          = "net.ipv4.conf.all.rp_filter"
	rpFilterInterfacePath = "net.ipv4.conf.%s.rp_filter"
	srcValidMarkPath      = "net.ipv4.conf.all.src_valid_mark"
)

// Setup configures sysctl settings for RP filtering and source validation.
func Setup(wgIface *iface.WGIface) (map[string]int, error) {
	keys := map[string]int{}
	var result *multierror.Error

	oldVal, err := Set(srcValidMarkPath, 1, false)
	if err != nil {
		result = multierror.Append(result, err)
	} else {
		keys[srcValidMarkPath] = oldVal
	}

	oldVal, err = Set(rpFilterPath, 2, true)
	if err != nil {
		result = multierror.Append(result, err)
	} else {
		keys[rpFilterPath] = oldVal
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		result = multierror.Append(result, fmt.Errorf("list interfaces: %w", err))
	}

	for _, intf := range interfaces {
		if intf.Name == "lo" || wgIface != nil && intf.Name == wgIface.Name() {
			continue
		}

		i := fmt.Sprintf(rpFilterInterfacePath, intf.Name)
		oldVal, err := Set(i, 2, true)
		if err != nil {
			result = multierror.Append(result, err)
		} else {
			keys[i] = oldVal
		}
	}

	return keys, nberrors.FormatErrorOrNil(result)
}

// Set sets a sysctl configuration, if onlyIfOne is true it will only set the new value if it's set to 1
func Set(key string, desiredValue int, onlyIfOne bool) (int, error) {
	path := fmt.Sprintf("/proc/sys/%s", strings.ReplaceAll(key, ".", "/"))
	currentValue, err := os.ReadFile(path)
	if err != nil {
		return -1, fmt.Errorf("read sysctl %s: %w", key, err)
	}

	currentV, err := strconv.Atoi(strings.TrimSpace(string(currentValue)))
	if err != nil && len(currentValue) > 0 {
		return -1, fmt.Errorf("convert current desiredValue to int: %w", err)
	}

	if currentV == desiredValue || onlyIfOne && currentV != 1 {
		return currentV, nil
	}

	//nolint:gosec
	if err := os.WriteFile(path, []byte(strconv.Itoa(desiredValue)), 0644); err != nil {
		return currentV, fmt.Errorf("write sysctl %s: %w", key, err)
	}
	log.Debugf("Set sysctl %s from %d to %d", key, currentV, desiredValue)

	return currentV, nil
}

// Cleanup resets sysctl settings to their original values.
func Cleanup(originalSettings map[string]int) error {
	var result *multierror.Error

	for key, value := range originalSettings {
		_, err := Set(key, value, false)
		if err != nil {
			result = multierror.Append(result, err)
		}
	}

	return nberrors.FormatErrorOrNil(result)
}
