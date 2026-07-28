package server

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	SchemeREL  = "rel"
	SchemeRELS = "rels"
)

// getInstanceURL checks if user supplied a URL scheme otherwise adds to the
// provided address according to TLS definition and parses the address before returning it
func getInstanceURL(exposedAddress string, tlsSupported bool) (*url.URL, error) {
	addr := exposedAddress
	split := strings.Split(exposedAddress, "://")
	switch {
	case len(split) == 1 && tlsSupported:
		addr = "rels://" + exposedAddress
	case len(split) == 1 && !tlsSupported:
		addr = "rel://" + exposedAddress
	case len(split) > 2:
		return nil, fmt.Errorf("invalid exposed address: %s", exposedAddress)
	}

	parsedURL, err := url.ParseRequestURI(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid exposed address: %v", err)
	}

	if parsedURL.Scheme != SchemeREL && parsedURL.Scheme != SchemeRELS {
		return nil, fmt.Errorf("invalid scheme: %s", parsedURL.Scheme)
	}

	// Validate scheme matches TLS configuration
	if tlsSupported && parsedURL.Scheme == SchemeREL {
		return nil, fmt.Errorf("non-TLS scheme '%s' provided but TLS is supported", SchemeREL)
	}

	return parsedURL, nil
}
