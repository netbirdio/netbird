package management_test

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	mgmt "github.com/wiretrustee/wiretrustee/management"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	"github.com/wiretrustee/wiretrustee/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
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

	Describe("Checking management service health", func() {
		Context("with the IsHealthy endpoint", func() {
			It("should be successful", func() {
				client := createRawClient(addr)
				healthy, err := client.IsHealthy(context.TODO(), &mgmtProto.Empty{})

				Expect(err).NotTo(HaveOccurred())
				Expect(healthy).ToNot(BeNil())
			})
		})
	})

	Describe("Getting service Wireguard public key", func() {
		Context("with the GetServerKey endpoint", func() {
			It("should be successful", func() {
				client := createRawClient(addr)
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
})

func createRawClient(addr string) mgmtProto.ManagementServiceClient {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    10 * time.Second,
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
