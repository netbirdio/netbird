package cmd

import (
	"context"
	"github.com/cenkalti/backoff/v4"
	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/client/internal"
	mgm "github.com/wiretrustee/wiretrustee/management/client"
	mgmProto "github.com/wiretrustee/wiretrustee/management/proto"
	signal "github.com/wiretrustee/wiretrustee/signal/client"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

var (
	upCmd = &cobra.Command{
		Use:   "up",
		Short: "install, login and start wiretrustee client",
		RunE: func(cmd *cobra.Command, args []string) error {
			SetFlagsFromEnvVars()
			err := loginCmd.RunE(cmd, args)
			if err != nil {
				return err
			}
			if logFile == "console" {
				return runClient()
			}

			s, err := newSVC(&program{}, newSVCConfig())
			if err != nil {
				cmd.PrintErrln(err)
				return err
			}

			srvStatus, err := s.Status()
			if err != nil {
				if err == service.ErrNotInstalled {
					log.Infof("%s. Installing it now", err.Error())
					e := installCmd.RunE(cmd, args)
					if e != nil {
						return e
					}
				} else {
					log.Warnf("failed retrieving service status: %v", err)
				}
			}
			if srvStatus == service.StatusRunning {
				stopCmd.Run(cmd, args)
			}
			return startCmd.RunE(cmd, args)
		},
	}
)

// createEngineConfig converts configuration received from Management Service to EngineConfig
func createEngineConfig(key wgtypes.Key, config *internal.Config, peerConfig *mgmProto.PeerConfig) (*internal.EngineConfig, error) {
	iFaceBlackList := make(map[string]struct{})
	for i := 0; i < len(config.IFaceBlackList); i += 2 {
		iFaceBlackList[config.IFaceBlackList[i]] = struct{}{}
	}

	return &internal.EngineConfig{
		WgIface:        config.WgIface,
		WgAddr:         peerConfig.Address,
		IFaceBlackList: iFaceBlackList,
		WgPrivateKey:   key,
	}, nil
}

// connectToSignal creates Signal Service client and established a connection
func connectToSignal(ctx context.Context, wtConfig *mgmProto.WiretrusteeConfig, ourPrivateKey wgtypes.Key) (*signal.Client, error) {
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
func connectToManagement(ctx context.Context, managementAddr string, ourPrivateKey wgtypes.Key, tlsEnabled bool) (*mgm.Client, *mgmProto.LoginResponse, error) {
	log.Debugf("connecting to management server %s", managementAddr)
	client, err := mgm.NewClient(ctx, managementAddr, ourPrivateKey, tlsEnabled)
	if err != nil {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "failed connecting to Management Service : %s", err)
	}
	log.Debugf("connected to management server %s", managementAddr)

	serverPublicKey, err := client.GetServerPublicKey()
	if err != nil {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "failed while getting Management Service public key: %s", err)
	}

	loginResp, err := client.Login(*serverPublicKey)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			log.Error("peer registration required. Please run wiretrustee login command first")
			return nil, nil, err
		} else {
			return nil, nil, err
		}
	}

	log.Debugf("peer logged in to Management Service %s", managementAddr)

	return client, loginResp, nil
}

func runClient() error {
	var backOff = &backoff.ExponentialBackOff{
		InitialInterval:     time.Second,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      24 * 3 * time.Hour, //stop the client after 3 days trying (must be a huge problem, e.g permission denied)
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}

	operation := func() error {

		config, err := internal.ReadConfig(managementURL, configPath)
		if err != nil {
			log.Errorf("failed reading config %s %v", configPath, err)
			return err
		}

		//validate our peer's Wireguard PRIVATE key
		myPrivateKey, err := wgtypes.ParseKey(config.PrivateKey)
		if err != nil {
			log.Errorf("failed parsing Wireguard key %s: [%s]", config.PrivateKey, err.Error())
			return err
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mgmTlsEnabled := false
		if config.ManagementURL.Scheme == "https" {
			mgmTlsEnabled = true
		}

		// connect (just a connection, no stream yet) and login to Management Service to get an initial global Wiretrustee config
		mgmClient, loginResp, err := connectToManagement(ctx, config.ManagementURL.Host, myPrivateKey, mgmTlsEnabled)
		if err != nil {
			log.Warn(err)
			return err
		}

		// with the global Wiretrustee config in hand connect (just a connection, no stream yet) Signal
		signalClient, err := connectToSignal(ctx, loginResp.GetWiretrusteeConfig(), myPrivateKey)
		if err != nil {
			log.Error(err)
			return err
		}

		peerConfig := loginResp.GetPeerConfig()

		engineConfig, err := createEngineConfig(myPrivateKey, config, peerConfig)
		if err != nil {
			log.Error(err)
			return err
		}

		// create start the Wiretrustee Engine that will connect to the Signal and Management streams and manage connections to remote peers.
		engine := internal.NewEngine(signalClient, mgmClient, engineConfig, cancel, ctx)
		err = engine.Start()
		if err != nil {
			log.Errorf("error while starting Wiretrustee Connection Engine: %s", err)
			return err
		}

		log.Print("Wiretrustee engine started, my IP is: ", peerConfig.Address)

		select {
		case <-stopCh:
		case <-ctx.Done():
		}

		backOff.Reset()

		err = mgmClient.Close()
		if err != nil {
			log.Errorf("failed closing Management Service client %v", err)
			return err
		}
		err = signalClient.Close()
		if err != nil {
			log.Errorf("failed closing Signal Service client %v", err)
			return err
		}

		err = engine.Stop()
		if err != nil {
			log.Errorf("failed stopping engine %v", err)
			return err
		}

		go func() {
			cleanupCh <- struct{}{}
		}()

		log.Info("stopped Wiretrustee client")

		return ctx.Err()
	}

	err := backoff.Retry(operation, backOff)
	if err != nil {
		log.Errorf("exiting client retry loop due to unrecoverable error: %s", err)
		return err
	}
	return nil
}
