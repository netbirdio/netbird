package server

import (
	"context"
	"strings"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/mcpapi"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/metrics"
)

// MCPBroker is management's OAuth authorization server for MCP clients. It is nil when the
// MCP endpoint is off or no PKCE flow is configured to log users in with.
func (s *BaseServer) MCPBroker() *mcpapi.Broker {
	return Create(s, func() *mcpapi.Broker {
		if !mcpapi.EnabledByEnv() {
			return nil
		}
		flow := mcpapi.FlowFromConfig(s.Config, s.OAuthConfigProvider())
		if flow == nil {
			log.Infof("MCP OAuth disabled: no PKCE authorization flow is configured, MCP clients must use a personal access token")
			return nil
		}
		secrets, err := mcpapi.ResolveSecrets(s.Config.DataStoreEncryptionKey)
		if err != nil {
			log.Warnf("MCP OAuth disabled, MCP clients must use a personal access token: %v", err)
			return nil
		}
		grants, err := mcpapi.NewGrantStore(context.Background(), nbcache.GetAddrFromEnv())
		if err != nil {
			log.Warnf("MCP OAuth disabled, MCP clients must use a personal access token: %v", err)
			return nil
		}
		broker, err := mcpapi.NewBroker(mcpapi.BrokerConfig{
			Flow:           flow,
			ClientSecret:   mcpapi.FlowClientSecret(s.Config, s.OAuthConfigProvider()),
			Secrets:        secrets,
			Grants:         grants,
			Identity:       s.AuthManager(),
			Accounts:       s.AccountManager(),
			Limiter:        s.RateLimiter(),
			BaseURL:        s.mcpBaseURL(),
			TrustedProxies: s.Config.ReverseProxy.TrustedHTTPProxies,
		})
		if err != nil {
			log.Warnf("MCP OAuth disabled, MCP clients must use a personal access token: %v", err)
			return nil
		}
		return broker
	})
}

// mcpBaseURL is the URL clients reach management at when the deployment knows it, which it
// does with the embedded IdP: the identity provider is served at <base>/oauth2. The broker
// then registers its callback where the embedded IdP allows it, whatever the reverse proxy
// in front forwards.
func (s *BaseServer) mcpBaseURL() string {
	if s.Config.EmbeddedIdP == nil || !s.Config.EmbeddedIdP.Enabled {
		return ""
	}
	// The same base the embedded IdP registers the callback under.
	return strings.TrimSuffix(s.Config.EmbeddedIdP.Issuer, "/oauth2")
}

// registerMCPEndpoints mounts the MCP endpoint on the API router, behind the API
// authentication, and the broker's endpoints, which bypass it. Tool calls are replayed
// against the API router, so they run the same handlers and permission checks as the REST API.
func (s *BaseServer) registerMCPEndpoints(apiRouter *mux.Router) error {
	if !mcpapi.EnabledByEnv() {
		return nil
	}
	opts := mcpapi.OptionsFromEnv()
	opts.Usage = s.mcpUsage()
	if err := mcpapi.RegisterEndpoints(apiRouter, apiRouter, opts); err != nil {
		return err
	}
	if broker := s.MCPBroker(); broker != nil {
		return broker.RegisterEndpoints(s.Router(), apiRouter)
	}
	return nil
}

// mcpUsage counts MCP tool calls for the self-hosted metrics.
func (s *BaseServer) mcpUsage() *mcpapi.Usage {
	return Create(s, mcpapi.NewUsage)
}

// mcpMetrics reports the MCP endpoint to the self-hosted metrics. It resolves the server's
// dependencies here, since the metrics worker calls it from its own goroutine.
func (s *BaseServer) mcpMetrics() func() metrics.MCPMetrics {
	enabled := mcpapi.EnabledByEnv()
	oauthEnabled := enabled && s.MCPBroker() != nil
	usage := s.mcpUsage()
	return func() metrics.MCPMetrics {
		calls, users := usage.LastDay(time.Now())
		return metrics.MCPMetrics{Enabled: enabled, OAuthEnabled: oauthEnabled, ToolCallsLastDay: calls, UsersLastDay: users}
	}
}
