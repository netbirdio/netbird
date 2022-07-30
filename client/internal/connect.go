package internal

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/client/ssh"
	nbStatus "github.com/netbirdio/netbird/client/status"
	mgmtcmd "github.com/netbirdio/netbird/management/cmd"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/system"

	"github.com/netbirdio/netbird/iface"
	mgm "github.com/netbirdio/netbird/management/client"
	mgmProto "github.com/netbirdio/netbird/management/proto"
	signal "github.com/netbirdio/netbird/signal/client"
	log "github.com/sirupsen/logrus"

	"github.com/cenkalti/backoff/v4"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

// RunClient with main logic.
func RunClient(ctx context.Context, config *Config, statusRecorder *nbStatus.Status) error {
	backOff := &backoff.ExponentialBackOff{
		InitialInterval:     time.Second,
		RandomizationFactor: 1,
		Multiplier:          1.7,
		MaxInterval:         15 * time.Second,
		MaxElapsedTime:      3 * 30 * 24 * time.Hour, // 3 months
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}

	state := CtxGetState(ctx)
	defer func() {
		s, err := state.Status()
		if err != nil || s != StatusNeedsLogin {
			state.Set(StatusIdle)
		}
	}()

	wrapErr := state.Wrap
	myPrivateKey, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		log.Errorf("failed parsing Wireguard key %s: [%s]", config.PrivateKey, err.Error())
		return wrapErr(err)
	}

	var mgmTlsEnabled bool
	if config.ManagementURL.Scheme == "https" {
		mgmTlsEnabled = true
	}

	publicSSHKey, err := ssh.GeneratePublicKey([]byte(config.SSHKey))
	if err != nil {
		return err
	}

	managementURL := config.ManagementURL.String()
	statusRecorder.MarkManagementDisconnected(managementURL)

	operation := func() error {
		// if context cancelled we not start new backoff cycle
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		state.Set(StatusConnecting)

		engineCtx, cancel := context.WithCancel(ctx)
		defer func() {
			statusRecorder.MarkManagementDisconnected(managementURL)
			statusRecorder.CleanLocalPeerState()
			cancel()
		}()

		// connect (just a connection, no stream yet) and login to Management Service to get an initial global Wiretrustee config
		mgmClient, loginResp, err := connectToManagement(engineCtx, config.ManagementURL.Host, myPrivateKey, mgmTlsEnabled,
			publicSSHKey)
		if err != nil {
			log.Debug(err)
			if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.PermissionDenied) {
				state.Set(StatusNeedsLogin)
				return backoff.Permanent(wrapErr(err)) // unrecoverable error
			}
			return wrapErr(err)
		}
		statusRecorder.MarkManagementConnected(managementURL)

		localPeerState := nbStatus.LocalPeerState{
			IP:              loginResp.GetPeerConfig().GetAddress(),
			PubKey:          myPrivateKey.PublicKey().String(),
			KernelInterface: iface.WireguardModExists(),
		}

		statusRecorder.UpdateLocalPeerState(localPeerState)

		signalURL := fmt.Sprintf("%s://%s",
			strings.ToLower(loginResp.GetWiretrusteeConfig().GetSignal().GetProtocol().String()),
			loginResp.GetWiretrusteeConfig().GetSignal().GetUri(),
		)

		statusRecorder.MarkSignalDisconnected(signalURL)
		defer statusRecorder.MarkSignalDisconnected(signalURL)

		// with the global Wiretrustee config in hand connect (just a connection, no stream yet) Signal
		signalClient, err := connectToSignal(engineCtx, loginResp.GetWiretrusteeConfig(), myPrivateKey)
		if err != nil {
			log.Error(err)
			return wrapErr(err)
		}

		statusRecorder.MarkSignalConnected(signalURL)

		peerConfig := loginResp.GetPeerConfig()

		engineConfig, err := createEngineConfig(myPrivateKey, config, peerConfig)
		if err != nil {
			log.Error(err)
			return wrapErr(err)
		}

		engine := NewEngine(engineCtx, cancel, signalClient, mgmClient, engineConfig, statusRecorder)
		err = engine.Start()
		if err != nil {
			log.Errorf("error while starting Netbird Connection Engine: %s", err)
			return wrapErr(err)
		}

		log.Print("Netbird engine started, my IP is: ", peerConfig.Address)
		state.Set(StatusConnected)

		<-engineCtx.Done()

		backOff.Reset()

		err = mgmClient.Close()
		if err != nil {
			log.Errorf("failed closing Management Service client %v", err)
			return wrapErr(err)
		}

		err = signalClient.Close()
		if err != nil {
			log.Errorf("failed closing Signal Service client %v", err)
			return wrapErr(err)
		}

		err = engine.Stop()
		if err != nil {
			log.Errorf("failed stopping engine %v", err)
			return wrapErr(err)
		}

		log.Info("stopped NetBird client")

		if _, err := state.Status(); err == ErrResetConnection {
			return err
		}

		return nil
	}

	err = backoff.Retry(operation, backOff)
	if err != nil {
		log.Debugf("exiting client retry loop due to unrecoverable error: %s", err)
		return err
	}
	return nil
}

// createEngineConfig converts configuration received from Management Service to EngineConfig
func createEngineConfig(key wgtypes.Key, config *Config, peerConfig *mgmProto.PeerConfig) (*EngineConfig, error) {

	engineConf := &EngineConfig{
		WgIfaceName:    config.WgIface,
		WgAddr:         peerConfig.Address,
		IFaceBlackList: config.IFaceBlackList,
		WgPrivateKey:   key,
		WgPort:         iface.DefaultWgPort,
		SSHKey:         []byte(config.SSHKey),
	}

	if config.PreSharedKey != "" {
		preSharedKey, err := wgtypes.ParseKey(config.PreSharedKey)
		if err != nil {
			return nil, err
		}
		engineConf.PreSharedKey = &preSharedKey
	}

	return engineConf, nil
}

// connectToSignal creates Signal Service client and established a connection
func connectToSignal(ctx context.Context, wtConfig *mgmProto.WiretrusteeConfig, ourPrivateKey wgtypes.Key) (*signal.GrpcClient, error) {
	var sigTLSEnabled bool
	if wtConfig.Signal.Protocol == mgmProto.HostConfig_HTTPS {
		sigTLSEnabled = true
	} else {
		sigTLSEnabled = false
	}

	signalClient, err := signal.NewClient(ctx, wtConfig.Signal.Uri, ourPrivateKey, sigTLSEnabled)
	if err != nil {
		log.Errorf("error while connecting to the Signal Exchange Service %s: %s", wtConfig.Signal.Uri, err)
		return nil, gstatus.Errorf(codes.FailedPrecondition, "failed connecting to Signal Service : %s", err)
	}

	return signalClient, nil
}

// connectToManagement creates Management Services client, establishes a connection, logs-in and gets a global Wiretrustee config (signal, turn, stun hosts, etc)
func connectToManagement(ctx context.Context, managementAddr string, ourPrivateKey wgtypes.Key, tlsEnabled bool, pubSSHKey []byte) (*mgm.GrpcClient, *mgmProto.LoginResponse, error) {
	log.Debugf("connecting to Management Service %s", managementAddr)
	client, err := mgm.NewClient(ctx, managementAddr, ourPrivateKey, tlsEnabled)
	if err != nil {
		return nil, nil, gstatus.Errorf(codes.FailedPrecondition, "failed connecting to Management Service : %s", err)
	}
	log.Debugf("connected to management server %s", managementAddr)

	serverPublicKey, err := client.GetServerPublicKey()
	if err != nil {
		return nil, nil, gstatus.Errorf(codes.FailedPrecondition, "failed while getting Management Service public key: %s", err)
	}

	sysInfo := system.GetInfo(ctx)
	loginResp, err := client.Login(*serverPublicKey, sysInfo, pubSSHKey)
	if err != nil {
		return nil, nil, err
	}

	log.Debugf("peer logged in to Management Service %s", managementAddr)

	return client, loginResp, nil
}

// CheckNewManagementPort checks whether client can switch to the new Management port 443.
// If it can switch, then it updates the config and returns a new one. Otherwise, it returns the provided config.
func CheckNewManagementPort(ctx context.Context, config *Config, configPath string) (*Config, error) {
	var mgmTlsEnabled bool
	if config.ManagementURL.Scheme == "https" {
		mgmTlsEnabled = true
	}

	if mgmTlsEnabled && config.ManagementURL.Port() == fmt.Sprintf("%d", mgmtcmd.ManagementLegacyPort) {
		// here we check whether we could switch from the legacy 33073 port to the new 443
		log.Infof("attempting to switch from the legacy Management port %d to the new port 443",
			mgmtcmd.ManagementLegacyPort)
		newURL := fmt.Sprintf("%s:%d", config.ManagementURL.Hostname(), 443)
		key, err := wgtypes.ParseKey(config.PrivateKey)
		if err != nil {
			log.Infof("couldn't switch to the new Management on port 443: %s", newURL)
			return config, err
		}

		_, err = mgm.NewClient(ctx, newURL, key, mgmTlsEnabled)
		if err != nil {
			log.Infof("couldn't switch to the new Management on port 443 %s", newURL)
			return config, err
		}

		config, err = ReadConfig(newURL, "", configPath, nil)
		if err != nil {
			log.Infof("couldn't switch to the new Management on port 443 %s", newURL)
			return config, fmt.Errorf("failed updating config file: %v", err)
		}
		log.Infof("successfully switched to the new Management port: %s", newURL)
	}

	return config, nil
}
