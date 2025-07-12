package server

import (
	"fmt"
	"net/url"
	"strings"
)

// getInstanceURL checks if user supplied a URL scheme otherwise adds to the
// provided address according to TLS definition and parses the address before returning it
func getInstanceURL(exposedAddress string, tlsSupported bool) (string, error) {
	addr := exposedAddress
	split := strings.Split(exposedAddress, "://")
	switch {
	case len(split) == 1 && tlsSupported:
		addr = "rels://" + exposedAddress
	case len(split) == 1 && !tlsSupported:
		addr = "rel://" + exposedAddress
	case len(split) > 2:
		return "", fmt.Errorf("invalid exposed address: %s", exposedAddress)
	}

	parsedURL, err := url.ParseRequestURI(addr)
	if err != nil {
		return "", fmt.Errorf("invalid exposed address: %v", err)
	}

	if parsedURL.Scheme != "rel" && parsedURL.Scheme != "rels" {
		return "", fmt.Errorf("invalid scheme: %s", parsedURL.Scheme)
	}

	return parsedURL.String(), nil
}
