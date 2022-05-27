package internal

import (
	"context"
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
	"google.golang.org/grpc/status"
)

// RunClient with main logic.
func RunClient(ctx context.Context, config *Config) error {
	backOff := &backoff.ExponentialBackOff{
		InitialInterval:     time.Second,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      24 * 3 * time.Hour, // stop the client after 3 days trying (must be a huge problem, e.g permission denied)
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
	operation := func() error {
		// if context cancelled we not start new backoff cycle
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		state.Set(StatusConnecting)
		// validate our peer's Wireguard PRIVATE key
		myPrivateKey, err := wgtypes.ParseKey(config.PrivateKey)
		if err != nil {
			log.Errorf("failed parsing Wireguard key %s: [%s]", config.PrivateKey, err.Error())
			return wrapErr(err)
		}

		var mgmTlsEnabled bool
		if config.ManagementURL.Scheme == "https" {
			mgmTlsEnabled = true
		}

		engineCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// connect (just a connection, no stream yet) and login to Management Service to get an initial global Wiretrustee config
		mgmClient, loginResp, err := connectToManagement(engineCtx, config.ManagementURL.Host, myPrivateKey, mgmTlsEnabled)
		if err != nil {
			log.Debug(err)
			if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
				log.Info("peer registration required. Please run `netbird status` for details")
				state.Set(StatusNeedsLogin)
				return nil
			}
			return wrapErr(err)
		}

		// with the global Wiretrustee config in hand connect (just a connection, no stream yet) Signal
		signalClient, err := connectToSignal(engineCtx, loginResp.GetWiretrusteeConfig(), myPrivateKey)
		if err != nil {
			log.Error(err)
			return wrapErr(err)
		}

		peerConfig := loginResp.GetPeerConfig()

		engineConfig, err := createEngineConfig(myPrivateKey, config, peerConfig)
		if err != nil {
			log.Error(err)
			return wrapErr(err)
		}

		engine := NewEngine(engineCtx, cancel, signalClient, mgmClient, engineConfig)
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

		log.Info("stopped Netbird client")

		if _, err := state.Status(); err == ErrResetConnection {
			return err
		}

		return nil
	}

	err := backoff.Retry(operation, backOff)
	if err != nil {
		log.Errorf("exiting client retry loop due to unrecoverable error: %s", err)
		return err
	}
	return nil
}

// createEngineConfig converts configuration received from Management Service to EngineConfig
func createEngineConfig(key wgtypes.Key, config *Config, peerConfig *mgmProto.PeerConfig) (*EngineConfig, error) {
	iFaceBlackList := make(map[string]struct{})
	for i := 0; i < len(config.IFaceBlackList); i += 2 {
		iFaceBlackList[config.IFaceBlackList[i]] = struct{}{}
	}

	engineConf := &EngineConfig{
		WgIfaceName:    config.WgIface,
		WgAddr:         peerConfig.Address,
		IFaceBlackList: iFaceBlackList,
		WgPrivateKey:   key,
		WgPort:         iface.DefaultWgPort,
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
		return nil, status.Errorf(codes.FailedPrecondition, "failed connecting to Signal Service : %s", err)
	}

	return signalClient, nil
}

// connectToManagement creates Management Services client, establishes a connection, logs-in and gets a global Wiretrustee config (signal, turn, stun hosts, etc)
func connectToManagement(ctx context.Context, managementAddr string, ourPrivateKey wgtypes.Key, tlsEnabled bool) (*mgm.GrpcClient, *mgmProto.LoginResponse, error) {
	log.Debugf("connecting to Management Service %s", managementAddr)
	client, err := mgm.NewClient(ctx, managementAddr, ourPrivateKey, tlsEnabled)
	if err != nil {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "failed connecting to Management Service : %s", err)
	}
	log.Debugf("connected to management server %s", managementAddr)

	serverPublicKey, err := client.GetServerPublicKey()
	if err != nil {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "failed while getting Management Service public key: %s", err)
	}

	sysInfo := system.GetInfo(ctx)
	loginResp, err := client.Login(*serverPublicKey, sysInfo)
	if err != nil {
		return nil, nil, err
	}

	log.Debugf("peer logged in to Management Service %s", managementAddr)

	return client, loginResp, nil
}
