package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"sync"
	"time"
)

// A set of tools to exchange connection details (Wireguard endpoints) with the remote peer.

// GrpcClient Wraps the Signal Exchange Service gRpc client
type GrpcClient struct {
	key        wgtypes.Key
	realClient proto.SignalExchangeClient
	signalConn *grpc.ClientConn
	ctx        context.Context
	stream     proto.SignalExchange_ConnectStreamClient
	// connectedCh used to notify goroutines waiting for the connection to the Signal stream
	connectedCh chan struct{}
	mux         sync.Mutex
	// streamConnected indicates whether this GrpcClient is streamConnected to the Signal stream
	status Status
}

func (c *GrpcClient) GetStatus() Status {
	return c.status
}

// Close Closes underlying connections to the Signal Exchange
func (c *GrpcClient) Close() error {
	return c.signalConn.Close()
}

// NewClient creates a new Signal GrpcClient
func NewClient(ctx context.Context, addr string, key wgtypes.Key, tlsEnabled bool) (*GrpcClient, error) {

	transportOption := grpc.WithInsecure()

	if tlsEnabled {
		transportOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
	}

	sigCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(
		sigCtx,
		addr,
		transportOption,
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    15 * time.Second,
			Timeout: 10 * time.Second,
		}))

	if err != nil {
		log.Errorf("failed to connect to the signalling server %v", err)
		return nil, err
	}

	return &GrpcClient{
		realClient: proto.NewSignalExchangeClient(conn),
		ctx:        ctx,
		signalConn: conn,
		key:        key,
		mux:        sync.Mutex{},
		status:     StreamDisconnected,
	}, nil
}

//defaultBackoff is a basic backoff mechanism for general issues
func defaultBackoff(ctx context.Context) backoff.BackOff {
	return backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     800 * time.Millisecond,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      12 * time.Hour, //stop after 12 hours of trying, the error will be propagated to the general retry of the client
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)

}

// Receive Connects to the Signal Exchange message stream and starts receiving messages.
// The messages will be handled by msgHandler function provided.
// This function is blocking and reconnects to the Signal Exchange if errors occur (e.g. Exchange restart)
// The connection retry logic will try to reconnect for 30 min and if wasn't successful will propagate the error to the function caller.
func (c *GrpcClient) Receive(msgHandler func(msg *proto.Message) error) error {

	var backOff = defaultBackoff(c.ctx)

	operation := func() error {

		c.notifyStreamDisconnected()

		log.Debugf("signal connection state %v", c.signalConn.GetState())
		if !c.ready() {
			return fmt.Errorf("no connection to signal")
		}

		// connect to Signal stream identifying ourselves with a public Wireguard key
		// todo once the key rotation logic has been implemented, consider changing to some other identifier (received from management)
		stream, err := c.connect(c.key.PublicKey().String())
		if err != nil {
			log.Warnf("streamDisconnected from the Signal Exchange due to an error: %v", err)
			return err
		}

		c.notifyStreamConnected()

		log.Infof("streamConnected to the Signal Service stream")

		// start receiving messages from the Signal stream (from other peers through signal)
		err = c.receive(stream, msgHandler)
		if err != nil {
			log.Warnf("streamDisconnected from the Signal Exchange due to an error: %v", err)
			backOff.Reset()
			return err
		}

		return nil
	}

	err := backoff.Retry(operation, backOff)
	if err != nil {
		log.Errorf("exiting Signal Service connection retry loop due to unrecoverable error: %s", err)
		return err
	}

	return nil
}
func (c *GrpcClient) notifyStreamDisconnected() {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.status = StreamDisconnected
}

func (c *GrpcClient) notifyStreamConnected() {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.status = StreamConnected
	if c.connectedCh != nil {
		// there are goroutines waiting on this channel -> release them
		close(c.connectedCh)
		c.connectedCh = nil
	}
}

func (c *GrpcClient) getStreamStatusChan() <-chan struct{} {
	c.mux.Lock()
	defer c.mux.Unlock()
	if c.connectedCh == nil {
		c.connectedCh = make(chan struct{})
	}
	return c.connectedCh
}

func (c *GrpcClient) connect(key string) (proto.SignalExchange_ConnectStreamClient, error) {
	c.stream = nil

	// add key fingerprint to the request header to be identified on the server side
	md := metadata.New(map[string]string{proto.HeaderId: key})
	ctx := metadata.NewOutgoingContext(c.ctx, md)

	stream, err := c.realClient.ConnectStream(ctx, grpc.WaitForReady(true))

	c.stream = stream
	if err != nil {
		return nil, err
	}
	// blocks
	header, err := c.stream.Header()
	if err != nil {
		return nil, err
	}
	registered := header.Get(proto.HeaderRegistered)
	if len(registered) == 0 {
		return nil, fmt.Errorf("didn't receive a registration header from the Signal server whille connecting to the streams")
	}

	return stream, nil
}

// ready indicates whether the client is okay and ready to be used
// for now it just checks whether gRPC connection to the service is in state Ready
func (c *GrpcClient) ready() bool {
	return c.signalConn.GetState() == connectivity.Ready
}

// WaitStreamConnected waits until the client is connected to the Signal stream
func (c *GrpcClient) WaitStreamConnected() {

	if c.status == StreamConnected {
		return
	}

	ch := c.getStreamStatusChan()
	select {
	case <-c.ctx.Done():
	case <-ch:
	}
}

// SendToStream sends a message to the remote Peer through the Signal Exchange using established stream connection to the Signal Server
// The Client.Receive method must be called before sending messages to establish initial connection to the Signal Exchange
// Client.connWg can be used to wait
func (c *GrpcClient) SendToStream(msg *proto.EncryptedMessage) error {
	if !c.ready() {
		return fmt.Errorf("no connection to signal")
	}
	if c.stream == nil {
		return fmt.Errorf("connection to the Signal Exchnage has not been established yet. Please call Client.Receive before sending messages")
	}

	err := c.stream.Send(msg)
	if err != nil {
		log.Errorf("error while sending message to peer [%s] [error: %v]", msg.RemoteKey, err)
		return err
	}

	return nil
}

// Send sends a message to the remote Peer through the Signal Exchange.
func (c *GrpcClient) Send(msg *proto.Message) error {

	if !c.ready() {
		return fmt.Errorf("no connection to signal")
	}

	encryptedMessage, err := encryptMessage(msg, c.key)
	if err != nil {
		return err
	}
	_, err = c.realClient.Send(c.ctx, encryptedMessage)
	if err != nil {
		return err
	}

	return nil
}

// receive receives messages from other peers coming through the Signal Exchange
func (c *GrpcClient) receive(stream proto.SignalExchange_ConnectStreamClient,
	msgHandler func(msg *proto.Message) error) error {

	for {
		msg, err := stream.Recv()
		if s, ok := status.FromError(err); ok && s.Code() == codes.Canceled {
			log.Warnf("stream canceled (usually indicates shutdown)")
			return err
		} else if s.Code() == codes.Unavailable {
			log.Warnf("Signal Service is unavailable")
			return err
		} else if err == io.EOF {
			log.Warnf("Signal Service stream closed by server")
			return err
		} else if err != nil {
			return err
		}
		log.Debugf("received a new message from Peer [fingerprint: %s]", msg.Key)

		decryptedMessage, err := decryptMessage(msg, c.key)
		if err != nil {
			log.Errorf("failed decrypting message of Peer [key: %s] error: [%s]", msg.Key, err.Error())
		}

		err = msgHandler(decryptedMessage)

		if err != nil {
			log.Errorf("error while handling message of Peer [key: %s] error: [%s]", msg.Key, err.Error())
			//todo send something??
		}
	}
}
