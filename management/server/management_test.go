package server_test

import (
	"context"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	sync2 "sync"
	"time"

	pb "github.com/golang/protobuf/proto" //nolint
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/encryption"
	mgmtProto "github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/util"
)

const (
	ValidSetupKey = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
	AccountKey    = "bf1c8084-ba50-4ce7-9439-34653001fc3b"
)

var _ = Describe("Management service", func() {
	var (
		addr         string
		s            *grpc.Server
		dataDir      string
		client       mgmtProto.ManagementServiceClient
		serverPubKey wgtypes.Key
		conn         *grpc.ClientConn
	)

	BeforeEach(func() {
		level, _ := log.ParseLevel("Debug")
		log.SetLevel(level)
		var err error
		dataDir, err = os.MkdirTemp("", "wiretrustee_mgmt_test_tmp_*")
		Expect(err).NotTo(HaveOccurred())

		err = util.CopyFileContents("testdata/store.json", filepath.Join(dataDir, "store.json"))
		Expect(err).NotTo(HaveOccurred())
		var listener net.Listener

		config := &server.Config{}
		_, err = util.ReadJson("testdata/management.json", config)
		Expect(err).NotTo(HaveOccurred())
		config.Datadir = dataDir

		s, listener = startServer(config)
		addr = listener.Addr().String()
		client, conn = createRawClient(addr)

		// s public key
		resp, err := client.GetServerKey(context.TODO(), &mgmtProto.Empty{})
		Expect(err).NotTo(HaveOccurred())
		serverPubKey, err = wgtypes.ParseKey(resp.Key)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		s.Stop()
		err := conn.Close()
		Expect(err).NotTo(HaveOccurred())
		os.RemoveAll(dataDir)
	})

	Context("when calling IsHealthy endpoint", func() {
		Specify("a non-error result is returned", func() {
			healthy, err := client.IsHealthy(context.TODO(), &mgmtProto.Empty{})

			Expect(err).NotTo(HaveOccurred())
			Expect(healthy).ToNot(BeNil())
		})
	})

	Context("when calling Sync endpoint", func() {
		Context("when there is a new peer registered", func() {
			Specify("a proper configuration is returned", func() {
				key, _ := wgtypes.GenerateKey()
				loginPeerWithValidSetupKey(serverPubKey, key, client)

				encryptedBytes, err := encryption.EncryptMessage(serverPubKey, key, &mgmtProto.SyncRequest{})
				Expect(err).NotTo(HaveOccurred())

				sync, err := client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
					WgPubKey: key.PublicKey().String(),
					Body:     encryptedBytes,
				})
				Expect(err).NotTo(HaveOccurred())

				encryptedResponse := &mgmtProto.EncryptedMessage{}
				err = sync.RecvMsg(encryptedResponse)
				Expect(err).NotTo(HaveOccurred())

				resp := &mgmtProto.SyncResponse{}
				err = encryption.DecryptMessage(serverPubKey, key, encryptedResponse.Body, resp)
				Expect(err).NotTo(HaveOccurred())

				expectedSignalConfig := &mgmtProto.HostConfig{
					Uri:      "signal.wiretrustee.com:10000",
					Protocol: mgmtProto.HostConfig_HTTP,
				}
				expectedStunsConfig := &mgmtProto.HostConfig{
					Uri:      "stun:stun.wiretrustee.com:3468",
					Protocol: mgmtProto.HostConfig_UDP,
				}
				expectedTRUNHost := &mgmtProto.HostConfig{
					Uri:      "turn:stun.wiretrustee.com:3468",
					Protocol: mgmtProto.HostConfig_UDP,
				}

				Expect(resp.WiretrusteeConfig.Signal).To(BeEquivalentTo(expectedSignalConfig))
				Expect(resp.WiretrusteeConfig.Stuns).To(ConsistOf(expectedStunsConfig))
				// TURN validation is special because credentials are dynamically generated
				Expect(resp.WiretrusteeConfig.Turns).To(HaveLen(1))
				actualTURN := resp.WiretrusteeConfig.Turns[0]
				Expect(len(actualTURN.User) > 0).To(BeTrue())
				Expect(actualTURN.HostConfig).To(BeEquivalentTo(expectedTRUNHost))
				Expect(len(resp.NetworkMap.OfflinePeers) == 0).To(BeTrue())
			})
		})

		Context("when there are 3 peers registered under one account", func() {
			Specify("a list containing other 2 peers is returned", func() {
				key, _ := wgtypes.GenerateKey()
				key1, _ := wgtypes.GenerateKey()
				key2, _ := wgtypes.GenerateKey()
				loginPeerWithValidSetupKey(serverPubKey, key, client)
				loginPeerWithValidSetupKey(serverPubKey, key1, client)
				loginPeerWithValidSetupKey(serverPubKey, key2, client)

				messageBytes, err := pb.Marshal(&mgmtProto.SyncRequest{})
				Expect(err).NotTo(HaveOccurred())
				encryptedBytes, err := encryption.Encrypt(messageBytes, serverPubKey, key)
				Expect(err).NotTo(HaveOccurred())

				sync, err := client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
					WgPubKey: key.PublicKey().String(),
					Body:     encryptedBytes,
				})
				Expect(err).NotTo(HaveOccurred())

				encryptedResponse := &mgmtProto.EncryptedMessage{}
				err = sync.RecvMsg(encryptedResponse)
				Expect(err).NotTo(HaveOccurred())
				decryptedBytes, err := encryption.Decrypt(encryptedResponse.Body, serverPubKey, key)
				Expect(err).NotTo(HaveOccurred())

				resp := &mgmtProto.SyncResponse{}
				err = pb.Unmarshal(decryptedBytes, resp)
				Expect(err).NotTo(HaveOccurred())

				Expect(resp.GetRemotePeers()).To(HaveLen(2))
				peers := []string{resp.GetRemotePeers()[0].WgPubKey, resp.GetRemotePeers()[1].WgPubKey}
				Expect(peers).To(ContainElements(key1.PublicKey().String(), key2.PublicKey().String()))
			})
		})

		Context("when there is a new peer registered", func() {
			Specify("an update is returned", func() {
				// register only a single peer
				key, _ := wgtypes.GenerateKey()
				loginPeerWithValidSetupKey(serverPubKey, key, client)

				messageBytes, err := pb.Marshal(&mgmtProto.SyncRequest{})
				Expect(err).NotTo(HaveOccurred())
				encryptedBytes, err := encryption.Encrypt(messageBytes, serverPubKey, key)
				Expect(err).NotTo(HaveOccurred())

				sync, err := client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
					WgPubKey: key.PublicKey().String(),
					Body:     encryptedBytes,
				})
				Expect(err).NotTo(HaveOccurred())

				// after the initial sync call we have 0 peer updates
				encryptedResponse := &mgmtProto.EncryptedMessage{}
				err = sync.RecvMsg(encryptedResponse)
				Expect(err).NotTo(HaveOccurred())
				decryptedBytes, err := encryption.Decrypt(encryptedResponse.Body, serverPubKey, key)
				Expect(err).NotTo(HaveOccurred())
				resp := &mgmtProto.SyncResponse{}
				err = pb.Unmarshal(decryptedBytes, resp)
				Expect(resp.GetRemotePeers()).To(HaveLen(0))

				wg := sync2.WaitGroup{}
				wg.Add(1)

				// continue listening on updates for a peer
				go func() {
					err = sync.RecvMsg(encryptedResponse)

					decryptedBytes, err = encryption.Decrypt(encryptedResponse.Body, serverPubKey, key)
					Expect(err).NotTo(HaveOccurred())
					resp = &mgmtProto.SyncResponse{}
					err = pb.Unmarshal(decryptedBytes, resp)
					wg.Done()
				}()

				// register a new peer
				key1, _ := wgtypes.GenerateKey()
				loginPeerWithValidSetupKey(serverPubKey, key1, client)

				wg.Wait()

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.GetRemotePeers()).To(HaveLen(1))
				Expect(resp.GetRemotePeers()[0].WgPubKey).To(BeEquivalentTo(key1.PublicKey().String()))
			})
		})
	})

	Context("when calling GetServerKey endpoint", func() {
		Specify("a public Wireguard key of the service is returned", func() {
			resp, err := client.GetServerKey(context.TODO(), &mgmtProto.Empty{})

			Expect(err).NotTo(HaveOccurred())
			Expect(resp).ToNot(BeNil())
			Expect(resp.Key).ToNot(BeNil())
			Expect(resp.ExpiresAt).ToNot(BeNil())

			// check if the key is a valid Wireguard key
			key, err := wgtypes.ParseKey(resp.Key)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).ToNot(BeNil())
		})
	})

	Context("when calling Login endpoint", func() {
		Context("with an invalid setup key", func() {
			Specify("an error is returned", func() {
				key, _ := wgtypes.GenerateKey()
				message, err := encryption.EncryptMessage(serverPubKey, key, &mgmtProto.LoginRequest{SetupKey: "invalid setup key",
					Meta: &mgmtProto.PeerSystemMeta{}})
				Expect(err).NotTo(HaveOccurred())

				resp, err := client.Login(context.TODO(), &mgmtProto.EncryptedMessage{
					WgPubKey: key.PublicKey().String(),
					Body:     message,
				})

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
			})
		})

		Context("with a valid setup key", func() {
			It("a non error result is returned", func() {
				key, _ := wgtypes.GenerateKey()
				resp := loginPeerWithValidSetupKey(serverPubKey, key, client)

				Expect(resp).ToNot(BeNil())
			})
		})

		Context("with a registered peer", func() {
			It("a non error result is returned", func() {
				key, _ := wgtypes.GenerateKey()
				regResp := loginPeerWithValidSetupKey(serverPubKey, key, client)
				Expect(regResp).NotTo(BeNil())

				// just login without registration
				message, err := encryption.EncryptMessage(serverPubKey, key, &mgmtProto.LoginRequest{Meta: &mgmtProto.PeerSystemMeta{}})
				Expect(err).NotTo(HaveOccurred())
				loginResp, err := client.Login(context.TODO(), &mgmtProto.EncryptedMessage{
					WgPubKey: key.PublicKey().String(),
					Body:     message,
				})

				Expect(err).NotTo(HaveOccurred())

				decryptedResp := &mgmtProto.LoginResponse{}
				err = encryption.DecryptMessage(serverPubKey, key, loginResp.Body, decryptedResp)
				Expect(err).NotTo(HaveOccurred())

				expectedSignalConfig := &mgmtProto.HostConfig{
					Uri:      "signal.wiretrustee.com:10000",
					Protocol: mgmtProto.HostConfig_HTTP,
				}
				expectedStunsConfig := &mgmtProto.HostConfig{
					Uri:      "stun:stun.wiretrustee.com:3468",
					Protocol: mgmtProto.HostConfig_UDP,
				}
				expectedTurnsConfig := &mgmtProto.ProtectedHostConfig{
					HostConfig: &mgmtProto.HostConfig{
						Uri:      "turn:stun.wiretrustee.com:3468",
						Protocol: mgmtProto.HostConfig_UDP,
					},
					User:     "some_user",
					Password: "some_password",
				}

				Expect(decryptedResp.GetWiretrusteeConfig().Signal).To(BeEquivalentTo(expectedSignalConfig))
				Expect(decryptedResp.GetWiretrusteeConfig().Stuns).To(ConsistOf(expectedStunsConfig))
				Expect(decryptedResp.GetWiretrusteeConfig().Turns).To(ConsistOf(expectedTurnsConfig))
			})
		})
	})

	Context("when there are 10 peers registered under one account", func() {
		Context("when there are 10 more peers registered under the same account", func() {
			Specify("all of the 10 peers will get updates of 10 newly registered peers", func() {
				initialPeers := 10
				additionalPeers := 10

				var peers []wgtypes.Key
				for i := 0; i < initialPeers; i++ {
					key, _ := wgtypes.GenerateKey()
					loginPeerWithValidSetupKey(serverPubKey, key, client)
					peers = append(peers, key)
				}

				wg := sync2.WaitGroup{}
				wg.Add(initialPeers + initialPeers*additionalPeers)

				var clients []mgmtProto.ManagementService_SyncClient
				for _, peer := range peers {
					messageBytes, err := pb.Marshal(&mgmtProto.SyncRequest{})
					Expect(err).NotTo(HaveOccurred())
					encryptedBytes, err := encryption.Encrypt(messageBytes, serverPubKey, peer)
					Expect(err).NotTo(HaveOccurred())

					// open stream
					sync, err := client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
						WgPubKey: peer.PublicKey().String(),
						Body:     encryptedBytes,
					})
					Expect(err).NotTo(HaveOccurred())
					clients = append(clients, sync)

					// receive stream
					peer := peer
					go func() {
						for {
							encryptedResponse := &mgmtProto.EncryptedMessage{}
							err = sync.RecvMsg(encryptedResponse)
							if err != nil {
								break
							}
							decryptedBytes, err := encryption.Decrypt(encryptedResponse.Body, serverPubKey, peer)
							Expect(err).NotTo(HaveOccurred())

							resp := &mgmtProto.SyncResponse{}
							err = pb.Unmarshal(decryptedBytes, resp)
							Expect(err).NotTo(HaveOccurred())
							if len(resp.GetRemotePeers()) > 0 {
								// only consider peer updates
								wg.Done()
							}
						}
					}()
				}

				time.Sleep(1 * time.Second)
				for i := 0; i < additionalPeers; i++ {
					key, _ := wgtypes.GenerateKey()
					loginPeerWithValidSetupKey(serverPubKey, key, client)
					r := rand.New(rand.NewSource(time.Now().UnixNano()))
					n := r.Intn(200)
					time.Sleep(time.Duration(n) * time.Millisecond)
				}

				wg.Wait()

				for _, syncClient := range clients {
					err := syncClient.CloseSend()
					Expect(err).NotTo(HaveOccurred())
				}
			})
		})
	})

	Context("when there are peers registered under one account concurrently", func() {
		Specify("then there are no duplicate IPs", func() {
			initialPeers := 30

			ipChannel := make(chan string, 20)
			for i := 0; i < initialPeers; i++ {
				go func() {
					defer GinkgoRecover()
					key, _ := wgtypes.GenerateKey()
					loginPeerWithValidSetupKey(serverPubKey, key, client)
					encryptedBytes, err := encryption.EncryptMessage(serverPubKey, key, &mgmtProto.SyncRequest{})
					Expect(err).NotTo(HaveOccurred())

					// open stream
					sync, err := client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
						WgPubKey: key.PublicKey().String(),
						Body:     encryptedBytes,
					})
					Expect(err).NotTo(HaveOccurred())
					encryptedResponse := &mgmtProto.EncryptedMessage{}
					err = sync.RecvMsg(encryptedResponse)
					Expect(err).NotTo(HaveOccurred())

					resp := &mgmtProto.SyncResponse{}
					err = encryption.DecryptMessage(serverPubKey, key, encryptedResponse.Body, resp)
					Expect(err).NotTo(HaveOccurred())

					ipChannel <- resp.GetPeerConfig().Address
				}()
			}

			ips := make(map[string]struct{})
			for ip := range ipChannel {
				if _, ok := ips[ip]; ok {
					Fail("found duplicate IP: " + ip)
				}
				ips[ip] = struct{}{}
				if len(ips) == initialPeers {
					break
				}
			}
			close(ipChannel)
		})
	})

	Context("after login two peers", func() {
		Specify("then they receive the same network", func() {
			key, _ := wgtypes.GenerateKey()
			firstLogin := loginPeerWithValidSetupKey(serverPubKey, key, client)
			key, _ = wgtypes.GenerateKey()
			secondLogin := loginPeerWithValidSetupKey(serverPubKey, key, client)

			_, firstLoginNetwork, err := net.ParseCIDR(firstLogin.GetPeerConfig().GetAddress())
			Expect(err).NotTo(HaveOccurred())
			_, secondLoginNetwork, err := net.ParseCIDR(secondLogin.GetPeerConfig().GetAddress())
			Expect(err).NotTo(HaveOccurred())

			Expect(secondLoginNetwork.String()).To(BeEquivalentTo(firstLoginNetwork.String()))
		})
	})
})

type MocIntegratedValidator struct {
}

func (a MocIntegratedValidator) ValidateExtraSettings(newExtraSettings *account.ExtraSettings, oldExtraSettings *account.ExtraSettings, peers map[string]*nbpeer.Peer, userID string, accountID string) error {
	return nil
}

func (a MocIntegratedValidator) ValidatePeer(update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *account.ExtraSettings) (*nbpeer.Peer, error) {
	return update, nil
}

func (a MocIntegratedValidator) GetValidatedPeers(accountID string, groups map[string]*group.Group, peers map[string]*nbpeer.Peer, extraSettings *account.ExtraSettings) (map[string]struct{}, error) {
	validatedPeers := make(map[string]struct{})
	for p := range peers {
		validatedPeers[p] = struct{}{}
	}
	return validatedPeers, nil
}

func (MocIntegratedValidator) PreparePeer(accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) *nbpeer.Peer {
	return peer
}

func (MocIntegratedValidator) IsNotValidPeer(accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) (bool, bool, error) {
	return false, false, nil
}

func (MocIntegratedValidator) PeerDeleted(_, _ string) error {
	return nil
}

func (MocIntegratedValidator) SetPeerInvalidationListener(func(accountID string)) {

}

func (MocIntegratedValidator) Stop() {}

func loginPeerWithValidSetupKey(serverPubKey wgtypes.Key, key wgtypes.Key, client mgmtProto.ManagementServiceClient) *mgmtProto.LoginResponse {
	defer GinkgoRecover()

	meta := &mgmtProto.PeerSystemMeta{
		Hostname:           key.PublicKey().String(),
		GoOS:               runtime.GOOS,
		OS:                 runtime.GOOS,
		Core:               "core",
		Platform:           "platform",
		Kernel:             "kernel",
		WiretrusteeVersion: "",
	}
	message, err := encryption.EncryptMessage(serverPubKey, key, &mgmtProto.LoginRequest{SetupKey: ValidSetupKey, Meta: meta})
	Expect(err).NotTo(HaveOccurred())

	resp, err := client.Login(context.TODO(), &mgmtProto.EncryptedMessage{
		WgPubKey: key.PublicKey().String(),
		Body:     message,
	})

	Expect(err).NotTo(HaveOccurred())

	loginResp := &mgmtProto.LoginResponse{}
	err = encryption.DecryptMessage(serverPubKey, key, resp.Body, loginResp)
	Expect(err).NotTo(HaveOccurred())
	return loginResp
}

func createRawClient(addr string) (mgmtProto.ManagementServiceClient, *grpc.ClientConn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    10 * time.Second,
			Timeout: 2 * time.Second,
		}))
	Expect(err).NotTo(HaveOccurred())

	return mgmtProto.NewManagementServiceClient(conn), conn
}

func startServer(config *server.Config) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	Expect(err).NotTo(HaveOccurred())
	s := grpc.NewServer()

	store, _, err := server.NewTestStoreFromJson(config.Datadir)
	if err != nil {
		log.Fatalf("failed creating a store: %s: %v", config.Datadir, err)
	}

	peersUpdateManager := server.NewPeersUpdateManager(nil)
	eventStore := &activity.InMemoryEventStore{}
	accountManager, err := server.BuildManager(store, peersUpdateManager, nil, "", "netbird.selfhosted",
		eventStore, nil, false, MocIntegratedValidator{})
	if err != nil {
		log.Fatalf("failed creating a manager: %v", err)
	}
	turnManager := server.NewTimeBasedAuthSecretsManager(peersUpdateManager, config.TURNConfig)
	mgmtServer, err := server.NewServer(config, accountManager, peersUpdateManager, turnManager, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)
	go func() {
		if err := s.Serve(lis); err != nil {
			Expect(err).NotTo(HaveOccurred())
		}
	}()

	return s, lis
}
