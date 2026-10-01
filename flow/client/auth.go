package client

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var _ credentials.PerRPCCredentials = (*authToken)(nil)

type authToken struct {
	metaMap map[string]string
}

func (t authToken) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return t.metaMap, nil
}

func (authToken) RequireTransportSecurity() bool {
	return false // Set to true if you want to require a secure connection
}

// WithAuthToken returns a DialOption which sets the receiver flow credentials and places auth state on each outbound RPC
func withAuthToken(payload, signature string) grpc.DialOption {
	value := fmt.Sprintf("%s.%s", signature, payload)
	authMap := map[string]string{
		"authorization": "Bearer " + value,
	}
	return grpc.WithPerRPCCredentials(authToken{metaMap: authMap})
}
