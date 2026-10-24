// Package mcpapi holds the OAuth 2.1 authorization server Model Context Protocol clients sign
// in with to reach management's MCP endpoint at /api/mcp. It renders its own consent, logs
// users in at the configured identity provider, and issues tokens bound to the endpoint and
// re-checked against the user on every call.
package mcpapi

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const (
	// EnvEnabled switches MCP support on. It is off unless set to a true value.
	EnvEnabled = "NB_MCP_ENABLED"

	// Path is where the MCP endpoint is mounted, relative to the API router.
	Path = "/mcp"

	serverTitle = "NetBird Management"
)

// EnabledByEnv reports whether NB_MCP_ENABLED asks for the endpoint. An unparseable value is
// logged and treated as off.
func EnabledByEnv() bool {
	val := os.Getenv(EnvEnabled)
	if val == "" {
		return false
	}
	enabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", EnvEnabled, err)
		return false
	}
	return enabled
}
