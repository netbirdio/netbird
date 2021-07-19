package management_test

import (
	"context"
	pb "github.com/golang/protobuf/proto"
	"github.com/wiretrustee/wiretrustee/signal"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
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
	)

	BeforeEach(func() {
		var err error
		dataDir, err = ioutil.TempDir("", "wiretrustee_mgmt_test_tmp_*")
		Expect(err).NotTo(HaveOccurred())

		err = util.CopyFileContents("testdata/store.json", filepath.Join(dataDir, "store.json"))
		Expect(err).NotTo(HaveOccurred())
		var listener net.Listener
		server, listener = startServer(dataDir)
		addr = listener.Addr().String()
		client = createRawClient(addr)

		// server public key
		resp, err := client.GetServerKey(context.TODO(), &mgmtProto.Empty{})
		Expect(err).NotTo(HaveOccurred())
		serverPubKey, err = wgtypes.ParseKey(resp.Key)
		Expect(err).NotTo(HaveOccurred())

	})

	AfterEach(func() {
		server.Stop()
		err := os.RemoveAll(tmpDir)
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
})

func registerPeerWithValidSetupKey(key wgtypes.Key, client mgmtProto.ManagementServiceClient) *mgmtProto.RegisterPeerResponse {

	resp, err := client.RegisterPeer(context.TODO(), &mgmtProto.RegisterPeerRequest{
		Key:      key.PublicKey().String(),
		SetupKey: ValidSetupKey,
	})

	Expect(err).NotTo(HaveOccurred())

	return resp

}

func createRawClient(addr string) mgmtProto.ManagementServiceClient {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    10 * time.Second,
			Timeout: 2 * time.Second,
		}))
	Expect(err).NotTo(HaveOccurred())

	return mgmtProto.NewManagementServiceClient(conn)
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
