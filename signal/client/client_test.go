package client

import (
	"context"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	sigProto "github.com/wiretrustee/wiretrustee/signal/proto"
	"github.com/wiretrustee/wiretrustee/signal/server"
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
		Context("between streamConnected peers", func() {
			It("should be successful", func() {

				var msgReceived sync.WaitGroup
				msgReceived.Add(2)

				var receivedOnA string
				var receivedOnB string

				// connect PeerA to Signal
				keyA, _ := wgtypes.GenerateKey()
				clientA := createSignalClient(addr, keyA)
				go func() {
					err := clientA.Receive(func(msg *sigProto.Message) error {
						receivedOnA = msg.GetBody().GetPayload()
						msgReceived.Done()
						return nil
					})
					if err != nil {
						return
					}
				}()
				clientA.WaitStreamConnected()

				// connect PeerB to Signal
				keyB, _ := wgtypes.GenerateKey()
				clientB := createSignalClient(addr, keyB)

				go func() {
					err := clientB.Receive(func(msg *sigProto.Message) error {
						receivedOnB = msg.GetBody().GetPayload()
						err := clientB.Send(&sigProto.Message{
							Key:       keyB.PublicKey().String(),
							RemoteKey: keyA.PublicKey().String(),
							Body:      &sigProto.Body{Payload: "pong"},
						})
						if err != nil {
							Fail("failed sending a message to PeerA")
						}
						msgReceived.Done()
						return nil
					})
					if err != nil {
						return
					}
				}()

				clientB.WaitStreamConnected()

				// PeerA initiates ping-pong
				err := clientA.Send(&sigProto.Message{
					Key:       keyA.PublicKey().String(),
					RemoteKey: keyB.PublicKey().String(),
					Body:      &sigProto.Body{Payload: "ping"},
				})
				if err != nil {
					Fail("failed sending a message to PeerB")
				}

				if waitTimeout(&msgReceived, 3*time.Second) {
					Fail("test timed out on waiting for peers to exchange messages")
				}

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
				go func() {
					err := client.Receive(func(msg *sigProto.Message) error {
						return nil
					})
					if err != nil {
						return
					}
				}()
				client.WaitStreamConnected()
				Expect(client).NotTo(BeNil())
			})
		})

		Context("with a raw client and no Id header", func() {
			It("should fail", func() {

				client := createRawSignalClient(addr)
				stream, err := client.ConnectStream(context.Background())
				if err != nil {
					Fail("error connecting to stream")
				}

				_, err = stream.Recv()

				Expect(stream).NotTo(BeNil())
				Expect(err).NotTo(BeNil())
			})
		})

		Context("with a raw client and with an Id header", func() {
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

func createSignalClient(addr string, key wgtypes.Key) *Client {
	var sigTLSEnabled = false
	client, err := NewClient(context.Background(), addr, key, sigTLSEnabled)
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
	sigProto.RegisterSignalExchangeServer(s, server.NewServer())
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, lis
}

// waitTimeout waits for the waitgroup for the specified max timeout.
// Returns true if waiting timed out.
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}
