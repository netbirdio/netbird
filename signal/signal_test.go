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
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"net"
	"sync"
	"time"
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

	Describe("Exchanging messages", func() {
		Context("between connected peers", func() {
			It("should be successful", func() {

				var msgReceived sync.WaitGroup
				msgReceived.Add(2)

				var receivedOnA string
				var receivedOnB string

				// connect PeerA to Signal
				keyA, _ := wgtypes.GenerateKey()
				clientA := createSignalClient(addr, keyA)
				clientA.Receive(func(msg *sigProto.Message) error {
					receivedOnA = msg.GetBody().GetPayload()
					msgReceived.Done()
					return nil
				})
				clientA.WaitConnected()

				// connect PeerB to Signal
				keyB, _ := wgtypes.GenerateKey()
				clientB := createSignalClient(addr, keyB)
				clientB.Receive(func(msg *sigProto.Message) error {
					receivedOnB = msg.GetBody().GetPayload()
					clientB.Send(&sigProto.Message{
						Key:       keyB.PublicKey().String(),
						RemoteKey: keyA.PublicKey().String(),
						Body:      &sigProto.Body{Payload: "pong"},
					})
					msgReceived.Done()
					return nil
				})
				clientB.WaitConnected()

				// PeerA initiates ping-pong
				clientA.Send(&sigProto.Message{
					Key:       keyA.PublicKey().String(),
					RemoteKey: keyB.PublicKey().String(),
					Body:      &sigProto.Body{Payload: "ping"},
				})

				msgReceived.Wait()

				Expect(receivedOnA).To(BeEquivalentTo("pong"))
				Expect(receivedOnB).To(BeEquivalentTo("ping"))

			})
		})
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

				_, err = stream.Recv()

				Expect(stream).NotTo(BeNil())
				Expect(err).NotTo(BeNil())
			})
		})

		Context("with a raw client and with an ID header", func() {
			It("should be successful", func() {

				md := metadata.New(map[string]string{sigProto.HeaderId: "peer"})
				ctx := metadata.NewOutgoingContext(context.Background(), md)

				client := createRawSignalClient(addr)
				stream, err := client.ConnectStream(ctx)

				Expect(stream).NotTo(BeNil())
				Expect(err).To(BeNil())
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
	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    3 * time.Second,
			Timeout: 2 * time.Second,
		}))
	if err != nil {
		Fail("failed creating raw signal client")
	}

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
