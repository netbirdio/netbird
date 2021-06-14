package signal_test

import (
	"context"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal"
	sigProto "github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"net"
)

var _ = Describe("Client", func() {

	var (
		addr     string
		listener net.Listener
		server   *grpc.Server
	)

	BeforeEach(func() {
		server, listener = startSignal()
		addr = listener.Addr().String()

	})

	AfterEach(func() {
		server.Stop()
		listener.Close()
	})

	Describe("Connecting to the Signal stream channel", func() {
		Context("with a signal client", func() {
			It("should be successful", func() {

				key, _ := wgtypes.GenerateKey()
				client := createSignalClient(addr, key)
				client.Receive(func(msg *sigProto.Message) error {
					return nil
				})
				client.WaitConnected()

				Expect(client).NotTo(BeNil())
			})
		})

		Context("with a raw client and no ID header", func() {
			It("should fail", func() {

				client := createRawSignalClient(addr)
				stream, err := client.ConnectStream(context.Background())

				Expect(stream).To(BeNil())
				Expect(err).NotTo(BeNil())
			})
		})

	})

})

func createSignalClient(addr string, key wgtypes.Key) *signal.Client {
	client, err := signal.NewClient(context.Background(), addr, key)
	if err != nil {
		Fail("failed creating signal client")
	}
	return client
}

func createRawSignalClient(addr string) sigProto.SignalExchangeClient {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure())
	if err != nil {
		Fail("failed creating raw signal client")
	}
	defer conn.Close()

	return sigProto.NewSignalExchangeClient(conn)
}

func startSignal() (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	s := grpc.NewServer()
	sigProto.RegisterSignalExchangeServer(s, signal.NewServer())
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, lis
}
