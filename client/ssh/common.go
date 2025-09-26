package ssh

import (
	"context"
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

const (
	NetBirdSSHConfigFile = "99-netbird.conf"

	UnixSSHConfigDir    = "/etc/ssh/ssh_config.d"
	WindowsSSHConfigDir = "ssh/ssh_config.d"
)

// RequestJWTToken requests or retrieves a JWT token for SSH authentication
func RequestJWTToken(ctx context.Context, client proto.DaemonServiceClient, stdout, stderr io.Writer, useCache bool) (string, error) {
	authResponse, err := client.RequestJWTAuth(ctx, &proto.RequestJWTAuthRequest{})
	if err != nil {
		return "", fmt.Errorf("request JWT auth: %w", err)
	}

	if useCache && authResponse.CachedToken != "" {
		log.Debug("Using cached authentication token")
		return authResponse.CachedToken, nil
	}

	if stderr != nil {
		_, _ = fmt.Fprintln(stderr, "SSH authentication required.")
		_, _ = fmt.Fprintf(stderr, "Please visit: %s\n", authResponse.VerificationURIComplete)
		if authResponse.UserCode != "" {
			_, _ = fmt.Fprintf(stderr, "Or visit: %s and enter code: %s\n", authResponse.VerificationURI, authResponse.UserCode)
		}
		_, _ = fmt.Fprintln(stderr, "Waiting for authentication...")
	}

	tokenResponse, err := client.WaitJWTToken(ctx, &proto.WaitJWTTokenRequest{
		DeviceCode: authResponse.DeviceCode,
		UserCode:   authResponse.UserCode,
	})
	if err != nil {
		return "", fmt.Errorf("wait for JWT token: %w", err)
	}

	if stdout != nil {
		_, _ = fmt.Fprintln(stdout, "Authentication successful!")
	}
	return tokenResponse.Token, nil
}
