package signal

import (
	"context"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal/proto"
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

// Wraps the Signal Exchange Service gRpc client
type Client struct {
	realClient proto.SignalExchangeClient
	signalConn *grpc.ClientConn
	ctx        context.Context
	stream     proto.SignalExchange_ConnectStreamClient
	//waiting group to notify once stream is connected
	connWg sync.WaitGroup //todo use a channel instead??
}

// Closes underlying connections to the Signal Exchange
func (client *Client) Close() error {
	return client.signalConn.Close()
}

func NewClient(addr string, ctx context.Context) (*Client, error) {

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

	return &Client{
		realClient: proto.NewSignalExchangeClient(conn),
		ctx:        ctx,
		signalConn: conn,
	}, nil
}

// Connects to the Signal Exchange message stream and starts receiving messages.
// The messages will be handled by msgHandler function provided.
// This function runs a goroutine underneath and reconnects to the Signal Exchange if errors occur (e.g. Exchange restart)
// The key is the identifier of our Peer (could be Wireguard public key)
func (client *Client) Receive(key string, msgHandler func(msg *proto.Message) error) {
	client.connWg.Add(1)
	go func() {
		operation := func() error {
			err := client.connect(key, msgHandler)
			if err != nil {
				log.Warnf("disconnected from the Signal Exchange due to an error %s. Retrying ... ", err)
				client.connWg.Add(1)
			}
			return err
		}

		err := backoff.Retry(operation, backoff.NewExponentialBackOff())
		if err != nil {
			log.Errorf("error while communicating with the Signal Exchange %s ", err)
			return
		}
	}()
}

func (client *Client) connect(key string, msgHandler func(msg *proto.Message) error) error {
	client.stream = nil

	// add key fingerprint to the request header to be identified on the server side
	md := metadata.New(map[string]string{proto.HeaderId: key})
	ctx := metadata.NewOutgoingContext(client.ctx, md)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := client.realClient.ConnectStream(ctx)

	client.stream = stream
	if err != nil {
		return err
	}
	//connection established we are good to go
	client.connWg.Done()

	log.Infof("connected to the Signal Exchange Stream")

	return client.receive(stream, msgHandler)
}

// Waits until the client is connected to the message stream
func (client *Client) WaitConnected() {
	client.connWg.Wait()
}

// Sends a message to the remote Peer through the Signal Exchange.
// The Client.Receive method must be called before sending messages to establish initial connection to the Signal Exchange
// Client.connWg can be used to wait
func (client *Client) Send(msg *proto.Message) error {

	_, err := client.realClient.Connect(context.TODO(), msg)

	/*if client.stream == nil {
		return fmt.Errorf("connection to the Signal Exchnage has not been established yet. Please call Client.Receive before sending messages")
	}

	err := client.stream.Send(msg)*/
	if err != nil {
		log.Errorf("error while sending message to peer [%s] [error: %v]", msg.RemoteKey, err)
		return err
	}

	return nil
}

// Receives messages from other peers coming through the Signal Exchange
func (client *Client) receive(stream proto.SignalExchange_ConnectStreamClient,
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
		log.Debugf("received a new message from Peer [fingerprint: %s] [type %s]", msg.Key, msg.Type)

		//todo decrypt
		err = msgHandler(msg)

		if err != nil {
			log.Errorf("error while handling message of Peer [key: %s] error: [%s]", msg.Key, err.Error())
			//todo send something??
		}
	}
}

func UnMarshalCredential(msg *proto.Message) (*Credential, error) {
	credential := strings.Split(msg.Body, ":")
	if len(credential) != 2 {
		return nil, fmt.Errorf("error parsing message body %s", msg.Body)
	}
	return &Credential{
		UFrag: credential[0],
		Pwd:   credential[1],
	}, nil
}

func MarshalCredential(ourKey string, remoteKey string, credential *Credential, t proto.Message_Type) *proto.Message {
	return &proto.Message{
		Type:      t,
		Key:       ourKey,
		RemoteKey: remoteKey,
		Body:      fmt.Sprintf("%s:%s", credential.UFrag, credential.Pwd),
	}
}

type Credential struct {
	UFrag string
	Pwd   string
}
