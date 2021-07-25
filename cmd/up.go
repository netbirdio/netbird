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
	"google.golang.org/grpc/keepalive"
)

var (
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

			mgmAddr := "localhost:33073" // todo read from config
			mgmCtx := context.Background()
			mgmConn, err := grpc.DialContext(
				mgmCtx,
				mgmAddr,
				grpc.WithInsecure(),
				grpc.WithBlock(),
				grpc.WithKeepaliveParams(keepalive.ClientParameters{
					Time:    3 * time.Second,
					Timeout: 2 * time.Second,
				}))

			if err != nil {
				log.Errorf("error while connecting to the Management Service %s: %s", mgmAddr, err)
				os.Exit(ExitSetupFailed)
			}
			defer mgmConn.Close()

			setupKey := "" // todo read from config
			mgmClient := mgm.NewManagementServiceClient(mgmConn)
			serverKeyResponse, err := mgmClient.GetServerKey(mgmCtx, &mgm.Empty{})
			if err != nil {
				// todo reconnect
				log.Errorf("error while getting server key: %s", err)
				os.Exit(ExitSetupFailed)
			}

			serverKey, err := wgtypes.ParseKey(serverKeyResponse.Key)
			if err != nil {
				log.Errorf("failed parsing Wireguard public server key %s: [%s]", serverKeyResponse.Key, err.Error())
				os.Exit(ExitSetupFailed)
			}

			_, err = mgmClient.RegisterPeer(mgmCtx, &mgm.RegisterPeerRequest{Key: myKey.String(), SetupKey: setupKey})
			if err != nil {
				// todo reconnect
				log.Errorf("error while registering account: %s", err)
				os.Exit(ExitSetupFailed)
			}
			log.Println("Peer registered")

			go updatePeers(mgmClient, serverKey, myKey)

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

func updatePeers(mgmClient mgm.ManagementServiceClient, remotePubKey wgtypes.Key, ourPrivateKey wgtypes.Key) {
	log.Printf("Getting peers updates")
	ctx := context.Background()
	req := &mgm.SyncRequest{}
	encryptedReq, err := encryption.EncryptMessage(remotePubKey, ourPrivateKey, req)
	if err != nil {
		// todo re-connect
		log.Errorf("Failed to encrypt message:", err)
	}

	syncReq := &mgm.EncryptedMessage{WgPubKey: ourPrivateKey.PublicKey().String(), Body: encryptedReq}
	stream, err := mgmClient.Sync(ctx, syncReq)
	if err != nil {
		// todo re-connect
		log.Errorf("Failed to open management stream: %s", err)
	}
	for {
		update, err := stream.Recv()
		if err == io.EOF {
			// todo re-connect
			break
		}
		if err != nil {
			// todo re-connect
			log.Errorf("Managment stream disconnected: %s", err)
		}

		log.Infof("Got peers update")
		resp := &mgm.SyncResponse{}
		err = encryption.DecryptMessage(remotePubKey, ourPrivateKey, update.Body, resp)
		if err != nil {
			// todo re-connect
			log.Errorf("Failed to decrypt message: %s", err)
		}

		for _, peer := range resp.Peers {
			log.Infof("Peer: %s", peer)
		}
	}
}
