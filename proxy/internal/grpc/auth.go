// Package grpc provides gRPC utilities for the proxy client.
package grpc

import (
	"context"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// EnvProxyAllowInsecure controls whether the proxy token can be sent over non-TLS connections.
const EnvProxyAllowInsecure = "NB_PROXY_ALLOW_INSECURE"

var _ credentials.PerRPCCredentials = (*proxyAuthToken)(nil)

type proxyAuthToken struct {
	token         string
	allowInsecure bool
}

func (t proxyAuthToken) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

// RequireTransportSecurity returns true by default to protect the token in transit.
// Set NB_PROXY_ALLOW_INSECURE=true to allow non-TLS connections (not recommended for production).
func (t proxyAuthToken) RequireTransportSecurity() bool {
	return !t.allowInsecure
}

// WithProxyToken returns a DialOption that sets the proxy access token on each outbound RPC.
func WithProxyToken(token string) grpc.DialOption {
	allowInsecure := false
	if val := os.Getenv(EnvProxyAllowInsecure); val != "" {
		parsed, err := strconv.ParseBool(val)
		if err != nil {
			log.Warnf("invalid value for %s: %v", EnvProxyAllowInsecure, err)
		} else {
			allowInsecure = parsed
		}
	}
	return grpc.WithPerRPCCredentials(proxyAuthToken{token: token, allowInsecure: allowInsecure})
}
