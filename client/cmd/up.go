package cmd

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/client/internal"
	"github.com/wiretrustee/wiretrustee/iface"
	mgm "github.com/wiretrustee/wiretrustee/management/client"
	mgmProto "github.com/wiretrustee/wiretrustee/management/proto"
	signal "github.com/wiretrustee/wiretrustee/signal/client"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	upCmd = &cobra.Command{
		Use:   "up",
		Short: "start wiretrustee",
		RunE: func(cmd *cobra.Command, args []string) error {
			InitLog(logLevel)

			config, err := internal.ReadConfig(managementURL, configPath)
			if err != nil {
				log.Errorf("failed reading config %s %v", configPath, err)
				//os.Exit(ExitSetupFailed)
				return err
			}

			//validate our peer's Wireguard PRIVATE key
			myPrivateKey, err := wgtypes.ParseKey(config.PrivateKey)
			if err != nil {
				log.Errorf("failed parsing Wireguard key %s: [%s]", config.PrivateKey, err.Error())
				//os.Exit(ExitSetupFailed)
				return err
			}

			ctx := context.Background()

			mgmTlsEnabled := false
			if config.ManagementURL.Scheme == "https" {
				mgmTlsEnabled = true
			}

			// connect (just a connection, no stream yet) and login to Management Service to get an initial global Wiretrustee config
			mgmClient, loginResp, err := connectToManagement(ctx, config.ManagementURL.Host, myPrivateKey, mgmTlsEnabled)
			if err != nil {
				log.Warn(err)
				//os.Exit(ExitSetupFailed)
				return err
			}

			// with the global Wiretrustee config in hand connect (just a connection, no stream yet) Signal
			signalClient, err := connectToSignal(ctx, loginResp.GetWiretrusteeConfig(), myPrivateKey)
			if err != nil {
				log.Error(err)
				//os.Exit(ExitSetupFailed)
				return err
			}

			engineConfig, err := createEngineConfig(myPrivateKey, config, loginResp.GetWiretrusteeConfig(), loginResp.GetPeerConfig())
			if err != nil {
				log.Error(err)
				//os.Exit(ExitSetupFailed)
				return err
			}

			// create start the Wiretrustee Engine that will connect to the Signal and Management streams and manage connections to remote peers.
			engine := internal.NewEngine(signalClient, mgmClient, engineConfig)
			err = engine.Start()
			if err != nil {
				log.Errorf("error while starting Wiretrustee Connection Engine: %s", err)
				//os.Exit(ExitSetupFailed)
				return err
			}

			SetupCloseHandler()
			<-stopCh
			log.Infof("receive signal to stop running")
			err = mgmClient.Close()
			if err != nil {
				log.Errorf("failed closing Management Service client %v", err)
				//os.Exit(ExitSetupFailed)
				return err
			}
			err = signalClient.Close()
			if err != nil {
				log.Errorf("failed closing Signal Service client %v", err)
				//os.Exit(ExitSetupFailed)
				return err
			}

			log.Debugf("removing Wiretrustee interface %s", config.WgIface)
			err = iface.Close()
			if err != nil {
				log.Errorf("failed closing Wiretrustee interface %s %v", config.WgIface, err)
				//os.Exit(ExitSetupFailed)
				return err
			}

			return nil
		},
	}
)

func init() {
}

// createEngineConfig converts configuration received from Management Service to EngineConfig
func createEngineConfig(key wgtypes.Key, config *internal.Config, wtConfig *mgmProto.WiretrusteeConfig, peerConfig *mgmProto.PeerConfig) (*internal.EngineConfig, error) {
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

	log.Infof("peer logged in to Management Service %s", managementAddr)

	return client, loginResp, nil
}
