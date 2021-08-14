package cmd

import (
	"bufio"
	"context"
	"fmt"
	"github.com/pion/ice/v2"
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
	"os"
	"strings"
)

var (
	managementAddr string

	upCmd = &cobra.Command{
		Use:   "up",
		Short: "start wiretrustee",
		Run: func(cmd *cobra.Command, args []string) {
			InitLog(logLevel)

			config, err := internal.GetConfig(managementAddr, configPath)
			if err != nil {
				log.Errorf("failed getting config %s %v", configPath, err)
				os.Exit(ExitSetupFailed)
			}

			//validate our peer's Wireguard PRIVATE key
			myPrivateKey, err := wgtypes.ParseKey(config.PrivateKey)
			if err != nil {
				log.Errorf("failed parsing Wireguard key %s: [%s]", config.PrivateKey, err.Error())
				os.Exit(ExitSetupFailed)
			}

			ctx := context.Background()

			// connect (just a connection, no stream yet) and login to Management Service to get an initial global Wiretrustee config
			mgmTlsEnabled := false
			mgmClient, loginResp, err := connectToManagement(ctx, config.ManagementAddr, myPrivateKey, mgmTlsEnabled)
			if err != nil {
				log.Error(err)
				os.Exit(ExitSetupFailed)
			}

			// with the global Wiretrustee config in hand connect (just a connection, no stream yet) Signal
			signalClient, err := connectToSignal(ctx, loginResp.GetWiretrusteeConfig(), myPrivateKey)
			if err != nil {
				log.Error(err)
				os.Exit(ExitSetupFailed)
			}

			engineConfig, err := createEngineConfig(myPrivateKey, config, loginResp.GetWiretrusteeConfig(), loginResp.GetPeerConfig())
			if err != nil {
				log.Error(err)
				os.Exit(ExitSetupFailed)
			}

			// create start the Wiretrustee Engine that will connect to the Signal and Management streams and manage connections to remote peers.
			engine := internal.NewEngine(signalClient, mgmClient, engineConfig)
			err = engine.Start()
			if err != nil {
				log.Errorf("error while starting Wiretrustee Connection Engine: %s", err)
				os.Exit(ExitSetupFailed)
			}

			SetupCloseHandler()
			<-stopCh
			log.Infof("receive signal to stop running")
			err = mgmClient.Close()
			if err != nil {
				log.Errorf("failed closing Management Service client %v", err)
			}
			err = signalClient.Close()
			if err != nil {
				log.Errorf("failed closing Signal Service client %v", err)
			}

			log.Debugf("removing Wiretrustee interface %s", config.WgIface)
			err = iface.Close()
			if err != nil {
				log.Errorf("failed closing Wiretrustee interface %s %v", config.WgIface, err)
			}
		},
	}
)

func init() {
	upCmd.PersistentFlags().StringVar(&managementAddr, "management-addr", "", "Management Service address (e.g. app.wiretrustee.com")
}

// createEngineConfig converts configuration received from Management Service to EngineConfig
func createEngineConfig(key wgtypes.Key, config *internal.Config, wtConfig *mgmProto.WiretrusteeConfig, peerConfig *mgmProto.PeerConfig) (*internal.EngineConfig, error) {
	iFaceBlackList := make(map[string]struct{})
	for i := 0; i < len(config.IFaceBlackList); i += 2 {
		iFaceBlackList[config.IFaceBlackList[i]] = struct{}{}
	}

	stunTurns, err := toStunTurnURLs(wtConfig)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "failed parsing STUN and TURN URLs received from Management Service : %s", err)
	}

	return &internal.EngineConfig{
		StunsTurns:     stunTurns,
		WgIface:        config.WgIface,
		WgAddr:         peerConfig.Address,
		IFaceBlackList: iFaceBlackList,
		WgPrivateKey:   key,
	}, nil
}

// toStunTurnURLs converts Wiretrustee STUN and TURN configs to ice.URL array
func toStunTurnURLs(wtConfig *mgmProto.WiretrusteeConfig) ([]*ice.URL, error) {

	var stunsTurns []*ice.URL
	for _, stun := range wtConfig.Stuns {
		url, err := ice.ParseURL(stun.Uri)
		if err != nil {
			return nil, err
		}
		stunsTurns = append(stunsTurns, url)
	}
	for _, turn := range wtConfig.Turns {
		url, err := ice.ParseURL(turn.HostConfig.Uri)
		if err != nil {
			return nil, err
		}
		url.Username = turn.User
		url.Password = turn.Password
		stunsTurns = append(stunsTurns, url)
	}

	return stunsTurns, nil
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

// connectToManagement creates Management Services client, establishes a connection and gets a global Wiretrustee config (signal, turn, stun hosts, etc)
func connectToManagement(ctx context.Context, managementAddr string, ourPrivateKey wgtypes.Key, tlsEnabled bool) (*mgm.Client, *mgmProto.LoginResponse, error) {
	log.Debugf("connecting to management server %s", managementAddr)
	mgmClient, err := mgm.NewClient(ctx, managementAddr, ourPrivateKey, tlsEnabled)
	if err != nil {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "failed connecting to Management Service : %s", err)
	}
	log.Debugf("connected to management server %s", managementAddr)

	serverKey, err := mgmClient.GetServerPublicKey()
	if err != nil {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "failed while getting Management Service public key: %s", err)
	}

	wtConfig, err := loginPeer(*serverKey, mgmClient)
	if err != nil {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "failed logging-in peer on Management Service : %s", err)
	}

	log.Debugf("peer logged in to Management Service %s", wtConfig)

	return mgmClient, wtConfig, nil
}

func registerPeer(serverPublicKey wgtypes.Key, client *mgm.Client) (*mgmProto.LoginResponse, error) {
	setupKey, err := promptPeerSetupKey()
	if err != nil {
		log.Errorf("failed getting setup key: %s", err)
		return nil, err
	}

	log.Debugf("sending peer registration request")
	loginResp, err := client.Register(serverPublicKey, *setupKey)
	if err != nil {
		log.Errorf("failed registering peer %v", err)
		return nil, err
	}

	return loginResp, nil
}

func loginPeer(serverPublicKey wgtypes.Key, client *mgm.Client) (*mgmProto.LoginResponse, error) {

	loginResp, err := client.Login(serverPublicKey)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			log.Debugf("peer registration required")
			return registerPeer(serverPublicKey, client)
		} else {
			return nil, err
		}
	}

	return loginResp, nil
}

// promptPeerSetupKey prompts user to input a Setup Key
func promptPeerSetupKey() (*string, error) {
	fmt.Print("Enter setup key: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	input = strings.TrimSuffix(input, "\n")

	if input == "" {
		fmt.Print("Specified key is empty, try again.")
		return promptPeerSetupKey()
	}

	return &input, err
}
