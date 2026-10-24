// Package mcpapi serves the management REST API as a Model Context Protocol server, together
// with the OAuth 2.1 authorization server MCP clients sign in with.
//
// Every tool except get_guide, which returns an embedded guide, maps onto one REST operation
// and is executed by replaying the call in-process against the API router, so a tool call and
// the matching HTTP request run the same handler, the same permission checks and return the
// same JSON. The endpoint is mounted behind the API authentication middleware and takes the
// caller identity from the request context.
package mcpapi

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const (
	// EnvEnabled switches the MCP endpoint and its authorization server on. They are off
	// unless it is set to a true value.
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
