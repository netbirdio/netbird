package management_test

import (
	"context"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	mgmt "github.com/wiretrustee/wiretrustee/management"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"io"
	"io/ioutil"
	"net"
	"os"
	"time"
)

var _ = Describe("Client", func() {

	var (
		addr   string
		server *grpc.Server
		tmpDir string
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = ioutil.TempDir("", "wiretrustee_mgmt_test_tmp_*")
		Expect(err).NotTo(HaveOccurred())
		err = copyFileContents("testdata/config.json", tmpDir+"config.json")
		Expect(err).NotTo(HaveOccurred())
		var listener net.Listener
		server, listener = startServer(tmpDir + "config.json")
		addr = listener.Addr().String()

	})

	AfterEach(func() {
		server.Stop()
		err := os.Remove(tmpDir)
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

				Expect(err).ToNot(BeNil())
				Expect(resp).To(BeNil())

			})
		})
	})

	Describe("Registration", func() {
		Context("of a new peer with a valid setup key", func() {
			It("should be successful", func() {

				key, _ := wgtypes.GenerateKey()
				setupKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB" //present in the testdata/config.json file

				client := createRawClient(addr)
				resp, err := client.RegisterPeer(context.TODO(), &mgmtProto.RegisterPeerRequest{
					Key:      key.PublicKey().String(),
					SetupKey: setupKey,
				})

				Expect(err).To(BeNil())
				Expect(resp).ToNot(BeNil())

			})
		})
	})

	//TODO add test with a valid setup KEY
	//TODO create manually a user file with valid keys

	/*Describe("Registration", func() {
		Context("of a new peer", func() {
			It("should ", func() {

				key, _ := wgtypes.GenerateKey()
				setupKey := "some_setup_key"

				client := createRawClient(addr)
				resp, err := client.RegisterPeer(context.TODO(), &mgmtProto.RegisterPeerRequest{
					Key:      key.PublicKey().String(),
					SetupKey: setupKey,
				})

				Expect(resp).ToNot(BeNil())
				Expect(err).To(BeNil())

			})
		})
	})*/
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

func startServer(config string) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	s := grpc.NewServer()
	server, err := mgmt.NewServer(config)
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

// copyFileContents copies the contents of the file named src to the file named
// by dst. The file will be created if it does not already exist. If the
// destination file exists, all it's contents will be replaced by the contents
// of the source file.
func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}
