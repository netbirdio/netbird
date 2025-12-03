package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	"github.com/netbirdio/netbird/client/proto"
)

const (
	NetBirdSSHConfigFile = "99-netbird.conf"

	UnixSSHConfigDir    = "/etc/ssh/ssh_config.d"
	WindowsSSHConfigDir = "ssh/ssh_config.d"
)

var (
	// ErrPeerNotFound indicates the peer was not found in the network
	ErrPeerNotFound = errors.New("peer not found in network")
	// ErrNoStoredKey indicates the peer has no stored SSH host key
	ErrNoStoredKey = errors.New("peer has no stored SSH host key")
)

// HostKeyVerifier provides SSH host key verification
type HostKeyVerifier interface {
	VerifySSHHostKey(peerAddress string, key []byte) error
}

// DaemonHostKeyVerifier implements HostKeyVerifier using the NetBird daemon
type DaemonHostKeyVerifier struct {
	client proto.DaemonServiceClient
}

// NewDaemonHostKeyVerifier creates a new daemon-based host key verifier
func NewDaemonHostKeyVerifier(client proto.DaemonServiceClient) *DaemonHostKeyVerifier {
	return &DaemonHostKeyVerifier{
		client: client,
	}
}

// VerifySSHHostKey verifies an SSH host key by querying the NetBird daemon
func (d *DaemonHostKeyVerifier) VerifySSHHostKey(peerAddress string, presentedKey []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, err := d.client.GetPeerSSHHostKey(ctx, &proto.GetPeerSSHHostKeyRequest{
		PeerAddress: peerAddress,
	})
	if err != nil {
		return err
	}

	if !response.GetFound() {
		return ErrPeerNotFound
	}

	storedKeyData := response.GetSshHostKey()

	return VerifyHostKey(storedKeyData, presentedKey, peerAddress)
}

// printAuthInstructions prints authentication instructions to stderr
func printAuthInstructions(stderr io.Writer, authResponse *proto.RequestJWTAuthResponse, browserWillOpen bool) {
	_, _ = fmt.Fprintln(stderr, "SSH authentication required.")

	if browserWillOpen {
		_, _ = fmt.Fprintln(stderr, "Please do the SSO login in your browser.")
		_, _ = fmt.Fprintln(stderr, "If your browser didn't open automatically, use this URL to log in:")
		_, _ = fmt.Fprintln(stderr)
	}

	_, _ = fmt.Fprintf(stderr, "%s\n", authResponse.VerificationURIComplete)

	if authResponse.UserCode != "" {
		_, _ = fmt.Fprintf(stderr, "Or visit: %s and enter code: %s\n", authResponse.VerificationURI, authResponse.UserCode)
	}

	if browserWillOpen {
		_, _ = fmt.Fprintln(stderr)
	}

	_, _ = fmt.Fprintln(stderr, "Waiting for authentication...")
}

// RequestJWTToken requests or retrieves a JWT token for SSH authentication
func RequestJWTToken(ctx context.Context, client proto.DaemonServiceClient, stdout, stderr io.Writer, useCache bool, hint string, openBrowser func(string) error) (string, error) {
	req := &proto.RequestJWTAuthRequest{}
	if hint != "" {
		req.Hint = &hint
	}
	authResponse, err := client.RequestJWTAuth(ctx, req)
	if err != nil {
		return "", fmt.Errorf("request JWT auth: %w", err)
	}

	if useCache && authResponse.CachedToken != "" {
		log.Debug("Using cached authentication token")
		return authResponse.CachedToken, nil
	}

	if stderr != nil {
		printAuthInstructions(stderr, authResponse, openBrowser != nil)
	}

	if openBrowser != nil {
		if err := openBrowser(authResponse.VerificationURIComplete); err != nil {
			log.Debugf("open browser: %v", err)
		}
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

// VerifyHostKey verifies an SSH host key against stored peer key data.
// Returns nil only if the presented key matches the stored key.
// Returns ErrNoStoredKey if storedKeyData is empty.
// Returns an error if the keys don't match or if parsing fails.
func VerifyHostKey(storedKeyData []byte, presentedKey []byte, peerAddress string) error {
	if len(storedKeyData) == 0 {
		return ErrNoStoredKey
	}

	storedPubKey, _, _, _, err := ssh.ParseAuthorizedKey(storedKeyData)
	if err != nil {
		return fmt.Errorf("parse stored SSH key for %s: %w", peerAddress, err)
	}

	if !bytes.Equal(presentedKey, storedPubKey.Marshal()) {
		return fmt.Errorf("SSH host key mismatch for %s", peerAddress)
	}

	return nil
}

// AddJWTAuth prepends JWT password authentication to existing auth methods.
// This ensures JWT auth is tried first while preserving any existing auth methods.
func AddJWTAuth(config *ssh.ClientConfig, jwtToken string) *ssh.ClientConfig {
	configWithJWT := *config
	configWithJWT.Auth = append([]ssh.AuthMethod{ssh.Password(jwtToken)}, config.Auth...)
	return &configWithJWT
}

// CreateHostKeyCallback creates an SSH host key verification callback using the provided verifier.
// It tries multiple addresses (hostname, IP) for the peer before failing.
func CreateHostKeyCallback(verifier HostKeyVerifier) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		addresses := buildAddressList(hostname, remote)
		presentedKey := key.Marshal()

		for _, addr := range addresses {
			if err := verifier.VerifySSHHostKey(addr, presentedKey); err != nil {
				if errors.Is(err, ErrPeerNotFound) {
					// Try other addresses for this peer
					continue
				}
				return err
			}
			// Verified
			return nil
		}

		return fmt.Errorf("SSH host key verification failed: peer %s not found in network", hostname)
	}
}

// buildAddressList creates a list of addresses to check for host key verification.
// It includes the original hostname and extracts the host part from the remote address if different.
func buildAddressList(hostname string, remote net.Addr) []string {
	addresses := []string{hostname}
	if host, _, err := net.SplitHostPort(remote.String()); err == nil {
		if host != hostname {
			addresses = append(addresses, host)
		}
	}
	return addresses
}
