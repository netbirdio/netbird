package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/domain"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

// ServerDomains represents the management server domains extracted from NetBird configuration
type ServerDomains struct {
	Signal domain.Domain
	Relay  []domain.Domain
	Flow   domain.Domain
	Stuns  []domain.Domain
	Turns  []domain.Domain
}

// ExtractFromNetbirdConfig extracts domain information from NetBird protobuf configuration
func ExtractFromNetbirdConfig(config *mgmProto.NetbirdConfig) ServerDomains {
	if config == nil {
		return ServerDomains{}
	}

	domains := ServerDomains{}

	domains.Signal = extractSignalDomain(config)
	domains.Relay = extractRelayDomains(config)
	domains.Flow = extractFlowDomain(config)
	domains.Stuns = extractStunDomains(config)
	domains.Turns = extractTurnDomains(config)

	return domains
}

// extractValidDomain extracts a valid domain from a URL, filtering out IP addresses
func extractValidDomain(rawURL string) (domain.Domain, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}

	// Try standard URL parsing first (handles https://, http://, rels://, etc.)
	if parsedURL, err := url.Parse(rawURL); err == nil && parsedURL.Hostname() != "" {
		return extractDomainFromHost(parsedURL.Hostname())
	}

	// Extract domain from various formats:
	// - stun:domain:port -> domain
	// - turns:domain:port?params -> domain
	// - domain:port -> domain
	host := rawURL

	// Remove scheme prefix (stun:, turn:, turns:)
	if colonIndex := strings.Index(host, ":"); colonIndex > 0 && colonIndex < 10 && !strings.Contains(host[:colonIndex], ".") {
		host = host[colonIndex+1:]
	}

	// Remove port suffix
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		host = hostOnly
	}

	// Remove query parameters
	if queryIndex := strings.Index(host, "?"); queryIndex > 0 {
		host = host[:queryIndex]
	}

	return extractDomainFromHost(host)
}

// extractDomainFromHost extracts domain from a host string, filtering out IP addresses
func extractDomainFromHost(host string) (domain.Domain, error) {
	if host == "" {
		return "", fmt.Errorf("empty host")
	}

	if _, err := netip.ParseAddr(host); err == nil {
		return "", fmt.Errorf("IP address not allowed: %s", host)
	}

	d, err := domain.FromString(host)
	if err != nil {
		return "", fmt.Errorf("invalid domain: %v", err)
	}

	return d, nil
}

// extractSingleDomain extracts a single domain from a URL with error logging
func extractSingleDomain(url, serviceType string) domain.Domain {
	if url == "" {
		return ""
	}

	d, err := extractValidDomain(url)
	if err != nil {
		log.Debugf("Skipping %s: %v", serviceType, err)
		return ""
	}

	return d
}

// extractMultipleDomains extracts multiple domains from URLs with error logging
func extractMultipleDomains(urls []string, serviceType string) []domain.Domain {
	var domains []domain.Domain
	for _, url := range urls {
		if url == "" {
			continue
		}
		d, err := extractValidDomain(url)
		if err != nil {
			log.Debugf("Skipping %s: %v", serviceType, err)
			continue
		}
		domains = append(domains, d)
	}
	return domains
}

// extractSignalDomain extracts the signal domain from NetBird configuration.
func extractSignalDomain(config *mgmProto.NetbirdConfig) domain.Domain {
	if config.Signal != nil {
		return extractSingleDomain(config.Signal.Uri, "signal")
	}
	return ""
}

// extractRelayDomains extracts relay server domains from NetBird configuration.
func extractRelayDomains(config *mgmProto.NetbirdConfig) []domain.Domain {
	if config.Relay != nil {
		return extractMultipleDomains(config.Relay.Urls, "relay")
	}
	return nil
}

// extractFlowDomain extracts the traffic flow domain from NetBird configuration.
func extractFlowDomain(config *mgmProto.NetbirdConfig) domain.Domain {
	if config.Flow != nil {
		return extractSingleDomain(config.Flow.Url, "flow")
	}
	return ""
}

// extractStunDomains extracts STUN server domains from NetBird configuration.
func extractStunDomains(config *mgmProto.NetbirdConfig) []domain.Domain {
	var urls []string
	for _, stun := range config.Stuns {
		if stun != nil && stun.Uri != "" {
			urls = append(urls, stun.Uri)
		}
	}
	return extractMultipleDomains(urls, "STUN")
}

// extractTurnDomains extracts TURN server domains from NetBird configuration.
func extractTurnDomains(config *mgmProto.NetbirdConfig) []domain.Domain {
	var urls []string
	for _, turn := range config.Turns {
		if turn != nil && turn.HostConfig != nil && turn.HostConfig.Uri != "" {
			urls = append(urls, turn.HostConfig.Uri)
		}
	}
	return extractMultipleDomains(urls, "TURN")
}
