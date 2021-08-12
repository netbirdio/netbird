package cmd

import (
	"bufio"
	"context"
	"fmt"
	"github.com/wiretrustee/wiretrustee/client/internal"
	"io"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/encryption"
	mgm "github.com/wiretrustee/wiretrustee/management/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
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

			myKey, err := wgtypes.ParseKey(config.PrivateKey)
			if err != nil {
				log.Errorf("failed parsing Wireguard key %s: [%s]", config.PrivateKey, err.Error())
				os.Exit(ExitSetupFailed)
			}

			processManagement(config.ManagementAddr, "", myKey)

			/*var sigTLSEnabled = false
			ctx := context.Background()
			signalClient, err := signal.NewClient(ctx, config.SignalAddr, myKey, sigTLSEnabled)
			if err != nil {
				log.Errorf("error while connecting to the Signal Exchange Service %s: %s", config.SignalAddr, err)
				os.Exit(ExitSetupFailed)
			}
			//todo proper close handling
			defer func() { signalClient.Close() }()

			iFaceBlackList := make(map[string]struct{})
			for i := 0; i < len(config.IFaceBlackList); i += 2 {
				iFaceBlackList[config.IFaceBlackList[i]] = struct{}{}
			}
			engine := internal.NewEngine(signalClient, config.StunTurnURLs, config.WgIface, config.WgAddr, iFaceBlackList)

			err = engine.Start(myKey, config.Peers)
			if err != nil {
				log.Errorf("error while starting the engine: %s", err)
				os.Exit(ExitSetupFailed)
			}*/
			//signalClient.WaitConnected()

			SetupCloseHandler()
			<-stopCh
			log.Println("Receive signal to stop running")
		},
	}
)

func init() {
	upCmd.PersistentFlags().StringVar(&managementAddr, "management-addr", "", "Management Service address (e.g. app.wiretrustee.com")
}

func processManagement(managementAddr string, setupKey string, ourPrivateKey wgtypes.Key) {
	err := connectToManagement(managementAddr, ourPrivateKey)
	if err != nil {
		log.Errorf("Failed to connect to managment server: %s", err)
		os.Exit(ExitSetupFailed)
	}

	for {
		_ = connectToManagement(managementAddr, ourPrivateKey)
	}
}

func registerPeer(ourPrivateKey wgtypes.Key, serverPublicKey wgtypes.Key, client mgm.ManagementServiceClient) (*mgm.WiretrusteeConfig, error) {
	setupKey, err := promptSetupKey()
	if err != nil {
		log.Errorf("failed getting setup key: %s", err)
		return nil, err
	}

	log.Debugf("sending peer registration request")
	registrationReq, err := encryption.EncryptMessage(serverPublicKey, ourPrivateKey, &mgm.LoginRequest{SetupKey: *setupKey})
	if err != nil {
		log.Errorf("failed to encrypt registration message: %s", err)
		return nil, err
	}
	resp, err := client.Login(context.Background(), &mgm.EncryptedMessage{WgPubKey: ourPrivateKey.PublicKey().String(), Body: registrationReq})
	if err != nil {
		log.Errorf("failed registering peer %v", err)
		return nil, err
	}

	loginResp := &mgm.LoginResponse{}
	err = encryption.DecryptMessage(serverPublicKey, ourPrivateKey, resp.Body, loginResp)
	if err != nil {
		log.Errorf("failed to decrypt registration message: %s", err)
		return nil, err
	}

	return loginResp.GetWiretrusteeConfig(), nil
}

func loginPeer(ourPrivateKey wgtypes.Key, serverPublicKey wgtypes.Key, client mgm.ManagementServiceClient) (*mgm.WiretrusteeConfig, error) {
	loginReq, err := encryption.EncryptMessage(serverPublicKey, ourPrivateKey, &mgm.LoginRequest{})
	if err != nil {
		log.Errorf("failed to encrypt message: %s", err)
		return nil, err
	}
	resp, err := client.Login(context.Background(), &mgm.EncryptedMessage{
		WgPubKey: ourPrivateKey.PublicKey().String(),
		Body:     loginReq,
	})

	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			log.Debugf("peer registration required")
			return registerPeer(ourPrivateKey, serverPublicKey, client)
		} else {
			return nil, err
		}
	}

	loginResp := &mgm.LoginResponse{}
	err = encryption.DecryptMessage(serverPublicKey, ourPrivateKey, resp.Body, loginResp)
	if err != nil {
		log.Errorf("failed to decrypt registration message: %s", err)
		return nil, err
	}

	return loginResp.WiretrusteeConfig, nil
}

func connectToManagement(managementAddr string, ourPrivateKey wgtypes.Key) error {
	log.Debugf("connecting to management server %s", managementAddr)
	mgmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mgmConn, err := grpc.DialContext(
		mgmCtx,
		managementAddr,
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    3 * time.Second,
			Timeout: 2 * time.Second,
		}))

	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "Error while connecting to the Management Service %s: %s", managementAddr, err)
	}
	defer mgmConn.Close()

	log.Debugf("connected to management server %s", managementAddr)

	mgmClient := mgm.NewManagementServiceClient(mgmConn)
	serverKeyResponse, err := mgmClient.GetServerKey(mgmCtx, &mgm.Empty{})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed while getting server key: %s", err)
	}

	serverKey, err := wgtypes.ParseKey(serverKeyResponse.Key)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed parsing Wireguard public server key %s: [%s]", serverKeyResponse.Key, err)
	}

	wtConfig, err := loginPeer(ourPrivateKey, serverKey, mgmClient)
	if err != nil {
		return err
	}

	log.Debugf("peer logged in %s", wtConfig)
	updatePeers(mgmClient, serverKey, ourPrivateKey)
	return nil
}

func promptSetupKey() (*string, error) {
	fmt.Print("Enter setup key: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	input = strings.TrimSuffix(input, "\n")

	if input == "" {
		fmt.Print("Specified key is empty, try again.")
		return promptSetupKey()
	}

	return &input, err
}

func updatePeers(mgmClient mgm.ManagementServiceClient, remotePubKey wgtypes.Key, ourPrivateKey wgtypes.Key) {
	log.Debugf("getting peers updates")
	ctx := context.Background()
	req := &mgm.SyncRequest{}
	encryptedReq, err := encryption.EncryptMessage(remotePubKey, ourPrivateKey, req)
	if err != nil {
		log.Errorf("Failed to encrypt message: %s", err)
		return
	}

	syncReq := &mgm.EncryptedMessage{WgPubKey: ourPrivateKey.PublicKey().String(), Body: encryptedReq}
	stream, err := mgmClient.Sync(ctx, syncReq)
	if err != nil {
		log.Errorf("Failed to open management stream: %s", err)
		return
	}
	for {
		update, err := stream.Recv()
		if err == io.EOF {
			log.Errorf("Managment stream was closed: %s", err)
			return
		}
		if err != nil {
			log.Errorf("Managment stream disconnected: %s", err)
			return
		}

		log.Debugf("got peers update")
		resp := &mgm.SyncResponse{}
		err = encryption.DecryptMessage(remotePubKey, ourPrivateKey, update.Body, resp)
		if err != nil {
			log.Errorf("Failed to decrypt message: %s", err)
			return
		}

		for _, peer := range resp.RemotePeers {
			log.Infof("Peer: %s", peer)
			//_ = addPeer(peer.WgPubKey, strings.Join(peer.AllowedIps, ","))
		}

		// for _, peer := range resp.RemotePeers {
		//	log.Infof("Peer: %s", peer.WgPubKey)
		//}
	}
}
