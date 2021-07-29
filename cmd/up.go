package cmd

import (
	"context"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/connection"
	"github.com/wiretrustee/wiretrustee/encryption"
	mgm "github.com/wiretrustee/wiretrustee/management/proto"
	sig "github.com/wiretrustee/wiretrustee/signal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

var (
	setupKey string

	upCmd = &cobra.Command{
		Use:   "up",
		Short: "start wiretrustee",
		Run: func(cmd *cobra.Command, args []string) {
			InitLog(logLevel)

			config, err := Read(configPath)
			if err != nil {
				log.Fatalf("Error reading config file, message: %v", err)
			}

			myKey, err := wgtypes.ParseKey(config.PrivateKey)
			if err != nil {
				log.Errorf("failed parsing Wireguard key %s: [%s]", config.PrivateKey, err.Error())
				os.Exit(ExitSetupFailed)
			}

			go processManagement(config.ManagementAddr, setupKey, myKey)

			ctx := context.Background()
			signalClient, err := sig.NewClient(ctx, config.SignalAddr, myKey)
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
			engine := connection.NewEngine(signalClient, config.StunTurnURLs, config.WgIface, config.WgAddr, iFaceBlackList)

			err = engine.Start(myKey, config.Peers)
			if err != nil {
				log.Errorf("error while starting the engine: %s", err)
				os.Exit(ExitSetupFailed)
			}
			//signalClient.WaitConnected()

			SetupCloseHandler()
			<-stopCh
			log.Println("Receive signal to stop running")
		},
	}
)

func init() {
	upCmd.PersistentFlags().StringVar(&setupKey, "setupKey", "", "Setup key to join a network, if not specified a new network will be created")
}

func processManagement(managementAddr string, setupKey string, ourPrivateKey wgtypes.Key) {
	err := connectToManagement(managementAddr, setupKey, ourPrivateKey)
	if err != nil {
		log.Errorf("Failed to connect to managment server: %s", err)
		os.Exit(ExitSetupFailed)
	}

	for {
		_ = connectToManagement(managementAddr, setupKey, ourPrivateKey)
	}
}

func connectToManagement(managementAddr string, setupKey string, ourPrivateKey wgtypes.Key) error {
	log.Printf("Connecting to management server %s", managementAddr)
	mgmCtx := context.Background()
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

	log.Printf("Connected to management server %s", managementAddr)

	mgmClient := mgm.NewManagementServiceClient(mgmConn)
	serverKeyResponse, err := mgmClient.GetServerKey(mgmCtx, &mgm.Empty{})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "Error while getting server key: %s", err)
	}

	serverKey, err := wgtypes.ParseKey(serverKeyResponse.Key)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "Failed parsing Wireguard public server key %s: [%s]", serverKeyResponse.Key, err)
	}

	_, err = mgmClient.RegisterPeer(mgmCtx, &mgm.RegisterPeerRequest{Key: ourPrivateKey.PublicKey().String(), SetupKey: setupKey})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "Error while registering account: %s", err)
	}

	log.Println("Peer registered")
	updatePeers(mgmClient, serverKey, ourPrivateKey)
	return nil
}

func updatePeers(mgmClient mgm.ManagementServiceClient, remotePubKey wgtypes.Key, ourPrivateKey wgtypes.Key) {
	log.Printf("Getting peers updates")
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

		log.Infof("Got peers update")
		resp := &mgm.SyncResponse{}
		err = encryption.DecryptMessage(remotePubKey, ourPrivateKey, update.Body, resp)
		if err != nil {
			log.Errorf("Failed to decrypt message: %s", err)
			return
		}

		for _, peer := range resp.Peers {
			log.Infof("Peer: %s", peer)
			addPeer(peer, "")
		}

		// for _, peer := range resp.RemotePeers {
		//	log.Infof("Peer: %s", peer.WgPubKey)
		//}
	}
}
