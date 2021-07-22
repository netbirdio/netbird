package signal

import (
	"context"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/common"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"strings"
	"sync"
	"time"
)

// A set of tools to exchange connection details (Wireguard endpoints) with the remote peer.

// Client Wraps the Signal Exchange Service gRpc client
type Client struct {
	key        wgtypes.Key
	realClient proto.SignalExchangeClient
	signalConn *grpc.ClientConn
	ctx        context.Context
	stream     proto.SignalExchange_ConnectStreamClient
	//waiting group to notify once stream is connected
	connWg *sync.WaitGroup //todo use a channel instead??
}

// Close Closes underlying connections to the Signal Exchange
func (c *Client) Close() error {
	return c.signalConn.Close()
}

// NewClient creates a new Signal client
func NewClient(ctx context.Context, addr string, key wgtypes.Key) (*Client, error) {

	conn, err := grpc.DialContext(
		ctx,
		addr,
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    3 * time.Second,
			Timeout: 2 * time.Second,
		}))

	if err != nil {
		log.Errorf("failed to connect to the signalling server %v", err)
		return nil, err
	}

	var wg sync.WaitGroup
	return &Client{
		realClient: proto.NewSignalExchangeClient(conn),
		ctx:        ctx,
		signalConn: conn,
		key:        key,
		connWg:     &wg,
	}, nil
}

// Receive Connects to the Signal Exchange message stream and starts receiving messages.
// The messages will be handled by msgHandler function provided.
// This function runs a goroutine underneath and reconnects to the Signal Exchange if errors occur (e.g. Exchange restart)
// The key is the identifier of our Peer (could be Wireguard public key)
func (c *Client) Receive(msgHandler func(msg *proto.Message) error) {
	c.connWg.Add(1)
	go func() {

		var backOff = &backoff.ExponentialBackOff{
			InitialInterval:     backoff.DefaultInitialInterval,
			RandomizationFactor: backoff.DefaultRandomizationFactor,
			Multiplier:          backoff.DefaultMultiplier,
			MaxInterval:         3 * time.Second,
			MaxElapsedTime:      time.Duration(0), //never stop
			Stop:                backoff.Stop,
			Clock:               backoff.SystemClock,
		}

		operation := func() error {
			err := c.connect(c.key.PublicKey().String(), msgHandler)
			if err != nil {
				log.Warnf("disconnected from the Signal Exchange due to an error %s. Retrying ... ", err)
				c.connWg.Add(1)
				return err
			}

			backOff.Reset()
			return nil
		}

		err := backoff.Retry(operation, backOff)
		if err != nil {
			log.Errorf("error while communicating with the Signal Exchange %s ", err)
			return
		}
	}()
}

func (c *Client) connect(key string, msgHandler func(msg *proto.Message) error) error {
	c.stream = nil

	// add key fingerprint to the request header to be identified on the server side
	md := metadata.New(map[string]string{proto.HeaderId: key})
	ctx := metadata.NewOutgoingContext(c.ctx, md)

	stream, err := c.realClient.ConnectStream(ctx, grpc.WaitForReady(true))

	c.stream = stream
	if err != nil {
		return err
	}
	// blocks
	header, err := c.stream.Header()
	if err != nil {
		return err
	}
	registered := header.Get(proto.HeaderRegistered)
	if len(registered) == 0 {
		return fmt.Errorf("didn't receive a registration header from the Signal server whille connecting to the streams")
	}
	//connection established we are good to use the stream
	c.connWg.Done()

	log.Infof("connected to the Signal Exchange Stream")

	return c.receive(stream, msgHandler)
}

// WaitConnected waits until the client is connected to the message stream
func (c *Client) WaitConnected() {
	c.connWg.Wait()
}

// SendToStream sends a message to the remote Peer through the Signal Exchange using established stream connection to the Signal Server
// The Client.Receive method must be called before sending messages to establish initial connection to the Signal Exchange
// Client.connWg can be used to wait
func (c *Client) SendToStream(msg *proto.EncryptedMessage) error {

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

// decryptMessage decrypts the body of the msg using Wireguard private key and Remote peer's public key
func (c *Client) decryptMessage(msg *proto.EncryptedMessage) (*proto.Message, error) {
	remoteKey, err := wgtypes.ParseKey(msg.GetKey())
	if err != nil {
		return nil, err
	}

	body := &proto.Body{}
	err = common.DecryptMessage(remoteKey, c.key, msg.GetBody(), body)
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
func (c *Client) encryptMessage(msg *proto.Message) (*proto.EncryptedMessage, error) {

	remoteKey, err := wgtypes.ParseKey(msg.RemoteKey)
	if err != nil {
		return nil, err
	}

	encryptedBody, err := common.EncryptMessage(remoteKey, c.key, msg.Body)
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
func (c *Client) Send(msg *proto.Message) error {

	encryptedMessage, err := c.encryptMessage(msg)
	if err != nil {
		return err
	}
	_, err = c.realClient.Send(context.TODO(), encryptedMessage)
	if err != nil {
		log.Errorf("error while sending message to peer [%s] [error: %v]", msg.RemoteKey, err)
		return err
	}

	return nil
}

// receive receives messages from other peers coming through the Signal Exchange
func (c *Client) receive(stream proto.SignalExchange_ConnectStreamClient,
	msgHandler func(msg *proto.Message) error) error {

	for {
		msg, err := stream.Recv()
		if s, ok := status.FromError(err); ok && s.Code() == codes.Canceled {
			log.Warnf("stream canceled (usually indicates shutdown)")
			return err
		} else if s.Code() == codes.Unavailable {
			log.Warnf("server has been stopped")
			return err
		} else if err == io.EOF {
			log.Warnf("stream closed by server")
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

// UnMarshalCredential parses the credentials from the message and returns a Credential instance
func UnMarshalCredential(msg *proto.Message) (*Credential, error) {

	credential := strings.Split(msg.GetBody().GetPayload(), ":")
	if len(credential) != 2 {
		return nil, fmt.Errorf("error parsing message body %s", msg.Body)
	}
	return &Credential{
		UFrag: credential[0],
		Pwd:   credential[1],
	}, nil
}

// MarshalCredential marsharl a Credential instance and returns a Message object
func MarshalCredential(myKey wgtypes.Key, remoteKey wgtypes.Key, credential *Credential, t proto.Body_Type) (*proto.Message, error) {
	return &proto.Message{
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey.String(),
		Body: &proto.Body{
			Type:    t,
			Payload: fmt.Sprintf("%s:%s", credential.UFrag, credential.Pwd),
		},
	}, nil
}

// Credential is an instance of a Client's Credential
type Credential struct {
	UFrag string
	Pwd   string
}
