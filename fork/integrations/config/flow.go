// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Environment variables steering the flow log pipeline. Collection is
// all-or-nothing: the three required variables must all be set, otherwise the
// pipeline stays off and a single warning states what is missing.
const (
	// EnvFlowGroups holds the comma-separated group IDs whose member peers collect flow logs.
	EnvFlowGroups = "NB_FLOW_GROUPS"
	// EnvFlowReceiverURL is the flow receiver gRPC address the agents connect to.
	EnvFlowReceiverURL = "NB_FLOW_RECEIVER_URL"
	// EnvFlowSigningKey is the HMAC key signing the per-peer flow tokens.
	EnvFlowSigningKey = "NB_FLOW_SIGNING_KEY"
	// EnvFlowInterval is the agent send interval as a Go duration.
	EnvFlowInterval = "NB_FLOW_INTERVAL"
	// EnvFlowDNSCollection enables collection of DNS flows on the agents.
	EnvFlowDNSCollection = "NB_FLOW_DNS_COLLECTION"
	// EnvFlowExitNodeCollection enables collection of exit node and exit route flows.
	EnvFlowExitNodeCollection = "NB_FLOW_EXITNODE_COLLECTION"
)

const (
	defaultFlowInterval = 5 * time.Minute
	flowTokenLifetime   = 24 * time.Hour
)

// FlowSettings is the resolved flow pipeline configuration. Values come from
// the process environment once per process lifetime; changing them requires a
// management restart, while group membership changes take effect on the next
// peer sync without a restart.
type FlowSettings struct {
	Enabled            bool
	Groups             []string
	ReceiverURL        string
	TokenSecret        string
	Interval           time.Duration
	DNSCollection      bool
	ExitNodeCollection bool
}

// LoadFlowSettings parses the flow environment variables exactly once.
func LoadFlowSettings() FlowSettings {
	return loadFlowSettings()
}

var loadFlowSettings = sync.OnceValue(readFlowSettings)

func readFlowSettings() FlowSettings {
	groups := parseGroupIDs(os.Getenv(EnvFlowGroups))
	url := strings.TrimSpace(os.Getenv(EnvFlowReceiverURL))
	secret := os.Getenv(EnvFlowSigningKey)

	settings := FlowSettings{
		Groups:             groups,
		ReceiverURL:        url,
		TokenSecret:        secret,
		Interval:           parseFlowInterval(os.Getenv(EnvFlowInterval)),
		DNSCollection:      parseBoolEnv(EnvFlowDNSCollection),
		ExitNodeCollection: parseBoolEnv(EnvFlowExitNodeCollection),
	}

	var missing []string
	if len(groups) == 0 {
		missing = append(missing, EnvFlowGroups)
	}
	if url == "" {
		missing = append(missing, EnvFlowReceiverURL)
	}
	if secret == "" {
		missing = append(missing, EnvFlowSigningKey)
	}
	if len(missing) > 0 {
		log.Warnf("network flow logging disabled, missing or empty: %s", strings.Join(missing, ", "))
		return settings
	}

	settings.Enabled = true
	log.Infof("network flow logging enabled for %d group(s), receiver %s, interval %s, dns %t, exit node %t",
		len(groups), url, settings.Interval, settings.DNSCollection, settings.ExitNodeCollection)
	return settings
}

// matchesAnyGroup reports whether the peer groups overlap the flow groups.
func (s FlowSettings) matchesAnyGroup(peerGroups []string) bool {
	for _, g := range peerGroups {
		if slices.Contains(s.Groups, g) {
			return true
		}
	}
	return false
}

type tokenClaims struct {
	PeerID    string `json:"peer_id"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// signToken builds the flow credentials the agent presents as
// "Bearer <signature>.<payload>" to the receiver.
func (s FlowSettings) signToken(peerID string) (payload, signature string) {
	now := time.Now()
	raw, err := json.Marshal(tokenClaims{
		PeerID:    peerID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(flowTokenLifetime).Unix(),
	})
	if err != nil {
		log.Errorf("failed to marshal flow token claims for peer %s: %v", peerID, err)
		return "", ""
	}
	payload = base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(s.TokenSecret))
	mac.Write([]byte(payload))
	signature = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload, signature
}

func parseGroupIDs(raw string) []string {
	var groups []string
	for _, g := range strings.Split(raw, ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	return groups
}

func parseFlowInterval(raw string) time.Duration {
	if raw == "" {
		return defaultFlowInterval
	}
	interval, err := time.ParseDuration(raw)
	if err != nil {
		log.Warnf("failed to parse %s: %v, using %s", EnvFlowInterval, err, defaultFlowInterval)
		return defaultFlowInterval
	}
	if interval <= 0 {
		log.Warnf("%s must be positive, using %s", EnvFlowInterval, defaultFlowInterval)
		return defaultFlowInterval
	}
	return interval
}

func parseBoolEnv(name string) bool {
	val := os.Getenv(name)
	if val == "" {
		return false
	}
	enabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", name, err)
		return false
	}
	return enabled
}
