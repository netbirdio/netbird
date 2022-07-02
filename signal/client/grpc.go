package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/signal/proto"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"sync"
	"time"
)

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
	// StreamConnected indicates whether this client is StreamConnected to the Signal stream
	status Status
}

func (c *GrpcClient) StreamConnected() bool {
	return c.status == StreamConnected
}

func (c *GrpcClient) GetStatus() Status {
	return c.status
}

// Close Closes underlying connections to the Signal Exchange
func (c *GrpcClient) Close() error {
	return c.signalConn.Close()
}

// NewClient creates a new Signal client
func NewClient(ctx context.Context, addr string, key wgtypes.Key, tlsEnabled bool) (*GrpcClient, error) {

	transportOption := grpc.WithTransportCredentials(insecure.NewCredentials())

	if tlsEnabled {
		transportOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
	}

	sigCtx, cancel := context.WithTimeout(ctx, time.Second*3)
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
		RandomizationFactor: 1,
		Multiplier:          1.7,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      3 * 30 * 24 * time.Hour, // 3 months
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
		connState := c.signalConn.GetState()
		if connState == connectivity.Shutdown {
			return backoff.Permanent(fmt.Errorf("connection to signal has been shut down"))
		} else if !(connState == connectivity.Ready || connState == connectivity.Idle) {
			c.signalConn.WaitForStateChange(c.ctx, connState)
			return fmt.Errorf("connection to signal is not ready and in %s state", connState)
		}

		// connect to Signal stream identifying ourselves with a public Wireguard key
		// todo once the key rotation logic has been implemented, consider changing to some other identifier (received from management)
		stream, err := c.connect(c.key.PublicKey().String())
		if err != nil {
			log.Warnf("disconnected from the Signal Exchange due to an error: %v", err)
			return err
		}

		c.notifyStreamConnected()

		log.Infof("connected to the Signal Service stream")

		// start receiving messages from the Signal stream (from other peers through signal)
		err = c.receive(stream, msgHandler)
		if err != nil {
			// we need this reset because after a successful connection and a consequent error, backoff lib doesn't
			// reset times and next try will start with a long delay
			backOff.Reset()
			return err
		}

		return nil
	}

	err := backoff.Retry(operation, backOff)
	if err != nil {
		log.Errorf("exiting the Signal service connection retry loop due to the unrecoverable error: %v", err)
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

// Ready indicates whether the client is okay and Ready to be used
// for now it just checks whether gRPC connection to the service is in state Ready
func (c *GrpcClient) Ready() bool {
	return c.signalConn.GetState() == connectivity.Ready || c.signalConn.GetState() == connectivity.Idle
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
// The GrpcClient.Receive method must be called before sending messages to establish initial connection to the Signal Exchange
// GrpcClient.connWg can be used to wait
func (c *GrpcClient) SendToStream(msg *proto.EncryptedMessage) error {
	if !c.Ready() {
		return fmt.Errorf("no connection to signal")
	}
	if c.stream == nil {
		return fmt.Errorf("connection to the Signal Exchnage has not been established yet. Please call GrpcClient.Receive before sending messages")
	}

	err := c.stream.Send(msg)
	if err != nil {
		log.Errorf("error while sending message to peer [%s] [error: %v]", msg.RemoteKey, err)
		return err
	}

	return nil
}

// decryptMessage decrypts the body of the msg using Wireguard private key and Remote peer's public key
func (c *GrpcClient) decryptMessage(msg *proto.EncryptedMessage) (*proto.Message, error) {
	remoteKey, err := wgtypes.ParseKey(msg.GetKey())
	if err != nil {
		return nil, err
	}

	body := &proto.Body{}
	err = encryption.DecryptMessage(remoteKey, c.key, msg.GetBody(), body)
	if err != nil {
		return nil, err
	}

	return &proto.Message{
		Key:       msg.Key,
		RemoteKey: msg.RemoteKey,
		Body:      body,
	}, nil
}

// encryptMessage encrypts the body of the msg using Wireguard private key and Remote peer's public key
func (c *GrpcClient) encryptMessage(msg *proto.Message) (*proto.EncryptedMessage, error) {

	remoteKey, err := wgtypes.ParseKey(msg.RemoteKey)
	if err != nil {
		return nil, err
	}

	encryptedBody, err := encryption.EncryptMessage(remoteKey, c.key, msg.Body)
	if err != nil {
		return nil, err
	}

	return &proto.EncryptedMessage{
		Key:       msg.GetKey(),
		RemoteKey: msg.GetRemoteKey(),
		Body:      encryptedBody,
	}, nil
}

// Send sends a message to the remote Peer through the Signal Exchange.
func (c *GrpcClient) Send(msg *proto.Message) error {

	if !c.Ready() {
		return fmt.Errorf("no connection to signal")
	}

	encryptedMessage, err := c.encryptMessage(msg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	_, err = c.realClient.Send(ctx, encryptedMessage)
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
			log.Debugf("stream canceled (usually indicates shutdown)")
			return err
		} else if s.Code() == codes.Unavailable {
			log.Debugf("Signal Service is unavailable")
			return err
		} else if err == io.EOF {
			log.Debugf("Signal Service stream closed by server")
			return err
		} else if err != nil {
			return err
		}
		log.Debugf("received a new message from Peer [fingerprint: %s]", msg.Key)

		decryptedMessage, err := c.decryptMessage(msg)
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
