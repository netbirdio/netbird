// Package externalipmap validates the --external-ip-map flag shared by the
// agent and the proxy.
package externalipmap

import (
	"fmt"
	"net"
	"strings"
)

const flagName = "external-ip-map"

// Validate checks each element is formatted as "IP", "IP/IP" or
// "IP/interface". The engine drops every mapping when one element fails to
// parse, so callers should reject bad input up front.
func Validate(list []string) error {
	for _, element := range list {
		if element == "" {
			return fmt.Errorf("empty string is not a valid input for %s", flagName)
		}

		subElements := strings.Split(element, "/")
		if len(subElements) > 2 {
			return fmt.Errorf("%s is not a valid input for %s. it should be formatted as \"String\" or \"String/String\"", element, flagName)
		}

		if !isValidIP(subElements[0]) {
			return fmt.Errorf("%s is not a valid input for %s. it should be formatted as \"IP\" or \"IP/IP\", or \"IP/Interface Name\"", element, flagName)
		}

		if len(subElements) == 2 {
			if err := validateInternal(subElements[1]); err != nil {
				return fmt.Errorf("%s is not a valid input for %s. it should be an IP string or a network name: %w", subElements[1], flagName, err)
			}
		}
	}
	return nil
}

func validateInternal(element string) error {
	if isValidIP(element) {
		return nil
	}
	validIface, err := isValidInterface(element)
	if err != nil {
		return fmt.Errorf("validate network interface name: %w", err)
	}
	if !validIface {
		return fmt.Errorf("invalid IP or network interface name not found")
	}
	return nil
}

// isValidIP uses net.ParseIP to match the engine's parser exactly.
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isValidInterface(name string) (bool, error) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}
	for _, iface := range netInterfaces {
		if iface.Name == name {
			return true, nil
		}
	}
	return false, nil
}
