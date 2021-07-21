package management_test

import (
	"context"
	pb "github.com/golang/protobuf/proto" //nolint
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	sync2 "sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	mgmt "github.com/wiretrustee/wiretrustee/management"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	"github.com/wiretrustee/wiretrustee/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

const (
	ValidSetupKey   = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
	InvalidSetupKey = "INVALID_SETUP_KEY"
)

var _ = Describe("Management service", func() {

	var (
		addr         string
		server       *grpc.Server
		tmpDir       string
		dataDir      string
		client       mgmtProto.ManagementServiceClient
		serverPubKey wgtypes.Key
		conn         *grpc.ClientConn
	)

	BeforeEach(func() {
		level, _ := log.ParseLevel("Debug")
		log.SetLevel(level)
		var err error
		dataDir, err = ioutil.TempDir("", "wiretrustee_mgmt_test_tmp_*")
		Expect(err).NotTo(HaveOccurred())

		err = util.CopyFileContents("testdata/store.json", filepath.Join(dataDir, "store.json"))
		Expect(err).NotTo(HaveOccurred())
		var listener net.Listener
		server, listener = startServer(dataDir)
		addr = listener.Addr().String()
		client, conn = createRawClient(addr)

		// server public key
		resp, err := client.GetServerKey(context.TODO(), &mgmtProto.Empty{})
		Expect(err).NotTo(HaveOccurred())
		serverPubKey, err = wgtypes.ParseKey(resp.Key)
		Expect(err).NotTo(HaveOccurred())

	})

	AfterEach(func() {
		server.Stop()
		err := conn.Close()
		Expect(err).NotTo(HaveOccurred())
		err = os.RemoveAll(tmpDir)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("when calling IsHealthy endpoint", func() {
		Specify("a non-error result is returned", func() {

			healthy, err := client.IsHealthy(context.TODO(), &mgmtProto.Empty{})

			Expect(err).NotTo(HaveOccurred())
			Expect(healthy).ToNot(BeNil())
		})
	})

	Context("when calling Sync endpoint", func() {

		Context("when there are 3 peers registered under one account", func() {
			Specify("a list containing other 2 peers is returned", func() {
				key, _ := wgtypes.GenerateKey()
				key1, _ := wgtypes.GenerateKey()
				key2, _ := wgtypes.GenerateKey()
				registerPeerWithValidSetupKey(key, client)
				registerPeerWithValidSetupKey(key1, client)
				registerPeerWithValidSetupKey(key2, client)

				messageBytes, err := pb.Marshal(&mgmtProto.SyncRequest{})
				Expect(err).NotTo(HaveOccurred())
				encryptedBytes, err := signal.Encrypt(messageBytes, serverPubKey, key)
				Expect(err).NotTo(HaveOccurred())

				sync, err := client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
					WgPubKey: key.PublicKey().String(),
					Body:     encryptedBytes,
				})
				Expect(err).NotTo(HaveOccurred())

				encryptedResponse := &mgmtProto.EncryptedMessage{}
				err = sync.RecvMsg(encryptedResponse)
				Expect(err).NotTo(HaveOccurred())
				decryptedBytes, err := signal.Decrypt(encryptedResponse.Body, serverPubKey, key)
				Expect(err).NotTo(HaveOccurred())

				resp := &mgmtProto.SyncResponse{}
				err = pb.Unmarshal(decryptedBytes, resp)
				Expect(err).NotTo(HaveOccurred())

				Expect(resp.Peers).To(HaveLen(2))
				Expect(resp.Peers).To(ContainElements(key1.PublicKey().String(), key2.PublicKey().String()))

			})
		})

		Context("when there is a new peer registered", func() {
			Specify("an update is returned", func() {
				// register only a single peer
				key, _ := wgtypes.GenerateKey()
				registerPeerWithValidSetupKey(key, client)

				messageBytes, err := pb.Marshal(&mgmtProto.SyncRequest{})
				Expect(err).NotTo(HaveOccurred())
				encryptedBytes, err := signal.Encrypt(messageBytes, serverPubKey, key)
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
				decryptedBytes, err := signal.Decrypt(encryptedResponse.Body, serverPubKey, key)
				Expect(err).NotTo(HaveOccurred())
				resp := &mgmtProto.SyncResponse{}
				err = pb.Unmarshal(decryptedBytes, resp)
				Expect(resp.Peers).To(HaveLen(0))

				wg := sync2.WaitGroup{}
				wg.Add(1)

				// continue listening on updates for a peer
				go func() {
					err = sync.RecvMsg(encryptedResponse)

					decryptedBytes, err = signal.Decrypt(encryptedResponse.Body, serverPubKey, key)
					Expect(err).NotTo(HaveOccurred())
					resp = &mgmtProto.SyncResponse{}
					err = pb.Unmarshal(decryptedBytes, resp)
					wg.Done()

				}()

				// register a new peer
				key1, _ := wgtypes.GenerateKey()
				registerPeerWithValidSetupKey(key1, client)

				wg.Wait()

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Peers).To(ContainElements(key1.PublicKey().String()))
				Expect(resp.Peers).To(HaveLen(1))
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

			//check if the key is a valid Wireguard key
			key, err := wgtypes.ParseKey(resp.Key)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).ToNot(BeNil())

		})
	})

	Context("when calling RegisterPeer endpoint", func() {

		Context("with an invalid setup key", func() {
			Specify("an error is returned", func() {

				key, _ := wgtypes.GenerateKey()
				resp, err := client.RegisterPeer(context.TODO(), &mgmtProto.RegisterPeerRequest{
					Key:      key.PublicKey().String(),
					SetupKey: InvalidSetupKey,
				})

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())

			})
		})

		Context("with a valid setup key", func() {
			It("a non error result is returned", func() {

				key, _ := wgtypes.GenerateKey()
				resp := registerPeerWithValidSetupKey(key, client)

				Expect(resp).ToNot(BeNil())

			})
		})
	})

	Context("when there are 50 peers registered under one account", func() {
		Context("when there are 10 more peers registered under the same account", func() {
			Specify("all of the 50 peers will get updates of 10 newly registered peers", func() {

				initialPeers := 50
				additionalPeers := 10

				var peers []wgtypes.Key
				for i := 0; i < initialPeers; i++ {
					key, _ := wgtypes.GenerateKey()
					registerPeerWithValidSetupKey(key, client)
					peers = append(peers, key)
				}

				wg := sync2.WaitGroup{}
				wg.Add(initialPeers + initialPeers*additionalPeers)
				for _, peer := range peers {
					messageBytes, err := pb.Marshal(&mgmtProto.SyncRequest{})
					Expect(err).NotTo(HaveOccurred())
					encryptedBytes, err := signal.Encrypt(messageBytes, serverPubKey, peer)
					Expect(err).NotTo(HaveOccurred())

					// receive stream
					peer := peer
					go func() {

						// open stream
						sync, err := client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
							WgPubKey: peer.PublicKey().String(),
							Body:     encryptedBytes,
						})
						Expect(err).NotTo(HaveOccurred())
						for {
							encryptedResponse := &mgmtProto.EncryptedMessage{}
							err = sync.RecvMsg(encryptedResponse)
							if err == io.EOF {
								break
							} else if err != nil {
								Expect(err).NotTo(HaveOccurred())
							}
							decryptedBytes, err := signal.Decrypt(encryptedResponse.Body, serverPubKey, peer)
							Expect(err).NotTo(HaveOccurred())

							resp := &mgmtProto.SyncResponse{}
							err = pb.Unmarshal(decryptedBytes, resp)
							Expect(err).NotTo(HaveOccurred())
							wg.Done()

						}
					}()
				}

				time.Sleep(1 * time.Second)
				for i := 0; i < additionalPeers; i++ {
					key, _ := wgtypes.GenerateKey()
					registerPeerWithValidSetupKey(key, client)
					rand.Seed(time.Now().UnixNano())
					n := rand.Intn(500)
					time.Sleep(time.Duration(n) * time.Millisecond)
				}

				wg.Wait()

			})
		})
	})
})

func registerPeerWithValidSetupKey(key wgtypes.Key, client mgmtProto.ManagementServiceClient) *mgmtProto.RegisterPeerResponse {

	resp, err := client.RegisterPeer(context.TODO(), &mgmtProto.RegisterPeerRequest{
		Key:      key.PublicKey().String(),
		SetupKey: ValidSetupKey,
	})

	Expect(err).NotTo(HaveOccurred())

	return resp

}

func createRawClient(addr string) (mgmtProto.ManagementServiceClient, *grpc.ClientConn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    10 * time.Second,
			Timeout: 2 * time.Second,
		}))
	Expect(err).NotTo(HaveOccurred())

	return mgmtProto.NewManagementServiceClient(conn), conn
}

func startServer(dataDir string) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	Expect(err).NotTo(HaveOccurred())
	s := grpc.NewServer()
	server, err := mgmt.NewServer(dataDir)
	Expect(err).NotTo(HaveOccurred())
	mgmtProto.RegisterManagementServiceServer(s, server)
	go func() {
		if err := s.Serve(lis); err != nil {
			Expect(err).NotTo(HaveOccurred())
		}
	}()

	return s, lis
}
