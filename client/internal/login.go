package internal

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// IsLoginRequired check that the server is support SSO or not
func IsLoginRequired(ctx context.Context, config *profilemanager.Config) (bool, error) {
	mgmURL := config.ManagementURL
	mgmClient, err := getMgmClient(ctx, config.PrivateKey, mgmURL)
	if err != nil {
		return false, err
	}
	defer func() {
		err = mgmClient.Close()
		if err != nil {
			cStatus, ok := status.FromError(err)
			if !ok || ok && cStatus.Code() != codes.Canceled {
				log.Warnf("failed to close the Management service client, err: %v", err)
			}
		}
	}()
	log.Debugf("connected to the Management service %s", mgmURL.String())

	pubSSHKey, err := ssh.GeneratePublicKey([]byte(config.SSHKey))
	if err != nil {
		return false, err
	}

	_, _, err = doMgmLogin(ctx, mgmClient, pubSSHKey, config)
	if isLoginNeeded(err) {
		return true, nil
	}
	return false, err
}

// Login or register the client
func Login(ctx context.Context, config *profilemanager.Config, setupKey string, jwtToken string) error {
	mgmClient, err := getMgmClient(ctx, config.PrivateKey, config.ManagementURL)
	if err != nil {
		return err
	}
	defer func() {
		err = mgmClient.Close()
		if err != nil {
			cStatus, ok := status.FromError(err)
			if !ok || ok && cStatus.Code() != codes.Canceled {
				log.Warnf("failed to close the Management service client, err: %v", err)
			}
		}
	}()
	log.Debugf("connected to the Management service %s", config.ManagementURL.String())

	pubSSHKey, err := ssh.GeneratePublicKey([]byte(config.SSHKey))
	if err != nil {
		return err
	}

	serverKey, _, err := doMgmLogin(ctx, mgmClient, pubSSHKey, config)
	if serverKey != nil && isRegistrationNeeded(err) {
		// Only attempt registration if we have credentials (setup key or JWT token)
		if setupKey == "" && jwtToken == "" {
			log.Debugf("peer registration required but no credentials provided")
			return err
		}
		log.Debugf("peer registration required")
		_, err = registerPeer(ctx, *serverKey, mgmClient, setupKey, jwtToken, pubSSHKey, config)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	return nil
}

func getMgmClient(ctx context.Context, privateKey string, mgmURL *url.URL) (*mgm.GrpcClient, error) {
	// validate our peer's Wireguard PRIVATE key
	myPrivateKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		log.Errorf("failed parsing Wireguard key %s: [%s]", privateKey, err.Error())
		return nil, err
	}

	var mgmTlsEnabled bool
	if mgmURL.Scheme == "https" {
		mgmTlsEnabled = true
	}

	log.Debugf("connecting to the Management service %s", mgmURL.String())
	mgmClient, err := mgm.NewClient(ctx, mgmURL.Host, myPrivateKey, mgmTlsEnabled)
	if err != nil {
		log.Errorf("failed connecting to the Management service %s %v", mgmURL.String(), err)
		return nil, err
	}
	return mgmClient, err
}

func doMgmLogin(ctx context.Context, mgmClient *mgm.GrpcClient, pubSSHKey []byte, config *profilemanager.Config) (*wgtypes.Key, *mgmProto.LoginResponse, error) {
	serverKey, err := mgmClient.GetServerPublicKey()
	if err != nil {
		log.Errorf("failed while getting Management Service public key: %v", err)
		return nil, nil, err
	}

	sysInfo := system.GetInfo(ctx)
	sysInfo.SetFlags(
		config.RosenpassEnabled,
		config.RosenpassPermissive,
		config.ServerSSHAllowed,
		config.DisableClientRoutes,
		config.DisableServerRoutes,
		config.DisableDNS,
		config.DisableFirewall,
		config.BlockLANAccess,
		config.BlockInbound,
		config.LazyConnectionEnabled,
		config.EnableSSHRoot,
		config.EnableSSHSFTP,
		config.EnableSSHLocalPortForwarding,
		config.EnableSSHRemotePortForwarding,
		config.DisableSSHAuth,
	)
	loginResp, err := mgmClient.Login(*serverKey, sysInfo, pubSSHKey, config.DNSLabels)
	return serverKey, loginResp, err
}

// registerPeer checks whether setupKey was provided via cmd line and if not then it prompts user to enter a key.
// Otherwise tries to register with the provided setupKey via command line.
func registerPeer(ctx context.Context, serverPublicKey wgtypes.Key, client *mgm.GrpcClient, setupKey string, jwtToken string, pubSSHKey []byte, config *profilemanager.Config) (*mgmProto.LoginResponse, error) {
	validSetupKey, err := uuid.Parse(setupKey)
	if err != nil && jwtToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "invalid setup-key or no sso information provided, err: %v", err)
	}

	log.Debugf("sending peer registration request to Management Service")
	info := system.GetInfo(ctx)
	info.SetFlags(
		config.RosenpassEnabled,
		config.RosenpassPermissive,
		config.ServerSSHAllowed,
		config.DisableClientRoutes,
		config.DisableServerRoutes,
		config.DisableDNS,
		config.DisableFirewall,
		config.BlockLANAccess,
		config.BlockInbound,
		config.LazyConnectionEnabled,
		config.EnableSSHRoot,
		config.EnableSSHSFTP,
		config.EnableSSHLocalPortForwarding,
		config.EnableSSHRemotePortForwarding,
		config.DisableSSHAuth,
	)
	loginResp, err := client.Register(serverPublicKey, validSetupKey.String(), jwtToken, info, pubSSHKey, config.DNSLabels)
	if err != nil {
		// Check if this is a timeout that might succeed on the server side
		if s, ok := status.FromError(err); ok && s.Code() == codes.DeadlineExceeded {
			log.Infof("registration request timed out, waiting for server to complete processing...")
			return retryLoginAfterRegistrationTimeout(ctx, client, serverPublicKey, pubSSHKey, config)
		}
		log.Errorf("failed registering peer %v", err)
		return nil, err
	}

	log.Infof("peer has been successfully registered on Management Service")

	return loginResp, nil
}

// retryLoginAfterRegistrationTimeout handles the case where a registration request times out
// but may have succeeded on the server side. It waits for the server to complete processing
// and then retries with login requests to avoid showing errors to the user.
func retryLoginAfterRegistrationTimeout(
	ctx context.Context,
	client *mgm.GrpcClient,
	serverPublicKey wgtypes.Key,
	pubSSHKey []byte,
	config *profilemanager.Config,
) (*mgmProto.LoginResponse, error) {
	// Wait periods between login attempts: 60s, 40s, 40s (total ~180s with attempts)
	waitPeriods := []time.Duration{60 * time.Second, 40 * time.Second, 40 * time.Second}

	for i, waitDuration := range waitPeriods {
		attemptNum := i + 1

		// Check if context is cancelled before sleeping
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// Sleep to allow server to complete registration
		log.Infof("waiting %v before login attempt %d/3...", waitDuration, attemptNum)
		select {
		case <-time.After(waitDuration):
			// Continue to login attempt
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		// Attempt login
		log.Debugf("attempting login %d/3 after registration timeout", attemptNum)
		sysInfo := system.GetInfo(ctx)
		sysInfo.SetFlags(
			config.RosenpassEnabled,
			config.RosenpassPermissive,
			config.ServerSSHAllowed,
			config.DisableClientRoutes,
			config.DisableServerRoutes,
			config.DisableDNS,
			config.DisableFirewall,
			config.BlockLANAccess,
			config.BlockInbound,
			config.LazyConnectionEnabled,
			config.EnableSSHRoot,
			config.EnableSSHSFTP,
			config.EnableSSHLocalPortForwarding,
			config.EnableSSHRemotePortForwarding,
			config.DisableSSHAuth,
		)

		loginResp, err := client.Login(serverPublicKey, sysInfo, pubSSHKey, config.DNSLabels)
		if err == nil {
			log.Infof("registration completed successfully on server (recovered from timeout)")
			return loginResp, nil
		}

		// Check error type
		if s, ok := status.FromError(err); ok {
			switch s.Code() {
			case codes.PermissionDenied, codes.NotFound:
				// Peer not ready yet, continue to next retry
				log.Debugf("peer not ready yet (attempt %d/3): %v", attemptNum, s.Code())
				continue
			default:
				// Unexpected error, return it
				log.Errorf("login attempt %d/3 failed with unexpected error: %v", attemptNum, err)
				return nil, fmt.Errorf("registration timed out and login recovery failed: %w", err)
			}
		}

		// Last attempt - return descriptive error
		if attemptNum == 3 {
			return nil, status.Errorf(codes.DeadlineExceeded,
				"peer registration is taking longer than expected, please try 'netbird up' again in a few minutes")
		}
	}

	// Should never reach here, but just in case
	return nil, status.Errorf(codes.DeadlineExceeded,
		"peer registration is taking longer than expected, please try 'netbird up' again in a few minutes")
}

func isLoginNeeded(err error) bool {
	if err == nil {
		return false
	}
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	if s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied {
		return true
	}
	return false
}

func isRegistrationNeeded(err error) bool {
	if err == nil {
		return false
	}
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	if s.Code() == codes.PermissionDenied {
		return true
	}
	return false
}
