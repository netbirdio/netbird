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
	"net"
	"time"
)

var _ = Describe("Client", func() {

	var (
		addr     string
		listener net.Listener
		server   *grpc.Server
	)

	BeforeEach(func() {
		server, listener = startServer()
		addr = listener.Addr().String()

	})

	AfterEach(func() {
		server.Stop()
		listener.Close()
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
		Context("of a new peer", func() {
			It("should be successful", func() {

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

func startServer() (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	s := grpc.NewServer()
	mgmtProto.RegisterManagementServiceServer(s, mgmt.NewServer())
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, lis
}
