package management_test

import (
	"context"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	mgmt "github.com/wiretrustee/wiretrustee/management"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	"github.com/wiretrustee/wiretrustee/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var _ = Describe("Client", func() {

	var (
		addr    string
		server  *grpc.Server
		tmpDir  string
		dataDir string
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

	})

	AfterEach(func() {
		server.Stop()
		err := os.RemoveAll(tmpDir)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("Service health", func() {
		Context("when it has been started", func() {
			It("should be ok", func() {
				client := createRawClient(addr)
				healthy, err := client.IsHealthy(context.TODO(), &mgmtProto.Empty{})

				Expect(healthy).ToNot(BeNil())
				Expect(err).To(BeNil())

			})
		})
	})

	Describe("Registration", func() {
		Context("of a new peer without a valid setup key", func() {
			It("should fail", func() {

				key, _ := wgtypes.GenerateKey()
				setupKey := "invalid_setup_key"

				client := createRawClient(addr)
				resp, err := client.RegisterPeer(context.TODO(), &mgmtProto.RegisterPeerRequest{
					Key:      key.PublicKey().String(),
					SetupKey: setupKey,
				})

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())

			})
		})
	})

	Describe("Registration", func() {
		Context("of a new peer with a valid setup key", func() {
			It("should be successful", func() {

				key, _ := wgtypes.GenerateKey()
				setupKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB" //present in the testdata/store.json file

				client := createRawClient(addr)
				resp, err := client.RegisterPeer(context.TODO(), &mgmtProto.RegisterPeerRequest{
					Key:      key.PublicKey().String(),
					SetupKey: setupKey,
				})

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).ToNot(BeNil())

			})
		})
	})

	Describe("Registration", func() {
		Context("of a new peer with a valid setup key", func() {
			It("should be persisted to a file", func() {

				key, _ := wgtypes.GenerateKey()
				setupKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB" //present in the testdata/store.json file

				client := createRawClient(addr)
				_, err := client.RegisterPeer(context.TODO(), &mgmtProto.RegisterPeerRequest{
					Key:      key.PublicKey().String(),
					SetupKey: setupKey,
				})

				Expect(err).NotTo(HaveOccurred())

				store, err := util.ReadJson(filepath.Join(dataDir, "store.json"), &mgmt.Store{})
				Expect(err).NotTo(HaveOccurred())

				Expect(store.(*mgmt.Store)).NotTo(BeNil())
				user := store.(*mgmt.Store).Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"]
				Expect(user.Peers[key.PublicKey().String()]).NotTo(BeNil())
				Expect(user.SetupKeys[strings.ToLower(setupKey)]).NotTo(BeNil())

			})
		})
	})
})

func createRawClient(addr string) mgmtProto.ManagementServiceClient {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    3 * time.Second,
			Timeout: 2 * time.Second,
		}))
	if err != nil {
		Fail("failed creating raw signal client")
	}

	return mgmtProto.NewManagementServiceClient(conn)
}

func startServer(dataDir string) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	s := grpc.NewServer()
	server, err := mgmt.NewServer(dataDir)
	if err != nil {
		panic(err)
	}
	mgmtProto.RegisterManagementServiceServer(s, server)
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, lis
}
