package internal

import (
	"context"
	"net/url"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/management/client"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

// IsLoginRequired check that the server is support SSO or not
func IsLoginRequired(ctx context.Context, privateKey string, mgmURL *url.URL, sshKey string) (bool, error) {
	// validate our peer's Wireguard PRIVATE key
	myPrivateKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		log.Errorf("failed parsing Wireguard key %s: [%s]", privateKey, err.Error())
		return false, err
	}

	var mgmTlsEnabled bool
	if mgmURL.Scheme == "https" {
		mgmTlsEnabled = true
	}

	log.Debugf("connecting to the Management service %s", mgmURL.String())
	mgmClient, err := mgm.NewClient(ctx, mgmURL.Host, myPrivateKey, mgmTlsEnabled)
	if err != nil {
		log.Errorf("failed connecting to the Management service %s %v", mgmURL.String(), err)
		return false, err
	}
	log.Debugf("connected to the Management service %s", mgmURL.String())
	defer func() {
		err = mgmClient.Close()
		if err != nil {
			cStatus, ok := status.FromError(err)
			if !ok || ok && cStatus.Code() != codes.Canceled {
				log.Warnf("failed to close the Management service client, err: %v", err)
			}
		}
	}()

	serverKey, err := mgmClient.GetServerPublicKey()
	if err != nil {
		log.Errorf("failed while getting Management Service public key: %v", err)
		return false, err
	}

	pubSSHKey, err := ssh.GeneratePublicKey([]byte(sshKey))
	if err != nil {
		return false, err
	}
	sysInfo := system.GetInfo(ctx)
	_, err = mgmClient.Login(*serverKey, sysInfo, pubSSHKey)
	if isLoginNeeded(err) {
		return true, nil
	}
	return false, err
}

// Login or register the client
func Login(ctx context.Context, config *Config, setupKey string, jwtToken string) error {
	// validate our peer's Wireguard PRIVATE key
	myPrivateKey, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		log.Errorf("failed parsing Wireguard key %s: [%s]", config.PrivateKey, err.Error())
		return err
	}

	var mgmTlsEnabled bool
	if config.ManagementURL.Scheme == "https" {
		mgmTlsEnabled = true
	}

	log.Debugf("connecting to the Management service %s", config.ManagementURL.String())
	mgmClient, err := mgm.NewClient(ctx, config.ManagementURL.Host, myPrivateKey, mgmTlsEnabled)
	if err != nil {
		log.Errorf("failed connecting to the Management service %s %v", config.ManagementURL.String(), err)
		return err
	}
	log.Debugf("connected to the Management service %s", config.ManagementURL.String())
	defer func() {
		err = mgmClient.Close()
		if err != nil {
			cStatus, ok := status.FromError(err)
			if !ok || ok && cStatus.Code() != codes.Canceled {
				log.Warnf("failed to close the Management service client, err: %v", err)
			}
		}
	}()

	serverKey, err := mgmClient.GetServerPublicKey()
	if err != nil {
		log.Errorf("failed while getting Management Service public key: %v", err)
		return err
	}

	pubSSHKey, err := ssh.GeneratePublicKey([]byte(config.SSHKey))
	if err != nil {
		return err
	}
	sysInfo := system.GetInfo(ctx)
	_, err = mgmClient.Login(*serverKey, sysInfo, pubSSHKey)
	if err == nil {
		return nil
	}

	if isRegistrationNeeded(err) {
		log.Debugf("peer registration required")
		_, err = registerPeer(ctx, *serverKey, mgmClient, setupKey, jwtToken, pubSSHKey)
		return err
	}

	return err
}

// registerPeer checks whether setupKey was provided via cmd line and if not then it prompts user to enter a key.
// Otherwise tries to register with the provided setupKey via command line.
func registerPeer(ctx context.Context, serverPublicKey wgtypes.Key, client *mgm.GrpcClient, setupKey string, jwtToken string, pubSSHKey []byte) (*mgmProto.LoginResponse, error) {
	validSetupKey, err := uuid.Parse(setupKey)
	if err != nil && jwtToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "invalid setup-key or no sso information provided, err: %v", err)
	}

	log.Debugf("sending peer registration request to Management Service")
	info := system.GetInfo(ctx)
	loginResp, err := client.Register(serverPublicKey, validSetupKey.String(), jwtToken, info, pubSSHKey)
	if err != nil {
		log.Errorf("failed registering peer %v,%s", err, validSetupKey.String())
		return nil, err
	}

	log.Infof("peer has been successfully registered on Management Service")

	return loginResp, nil
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
