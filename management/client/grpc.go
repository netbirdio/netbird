package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/client/system"
	"github.com/wiretrustee/wiretrustee/encryption"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"io"
	"time"
)

type GrpcClient struct {
	key        wgtypes.Key
	realClient proto.ManagementServiceClient
	ctx        context.Context
	conn       *grpc.ClientConn
}

// NewClient creates a new client to Management service
func NewClient(ctx context.Context, addr string, ourPrivateKey wgtypes.Key, tlsEnabled bool) (*GrpcClient, error) {

	transportOption := grpc.WithTransportCredentials(insecure.NewCredentials())

	if tlsEnabled {
		transportOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
	}

	mgmCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(
		mgmCtx,
		addr,
		transportOption,
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    15 * time.Second,
			Timeout: 10 * time.Second,
		}))

	if err != nil {
		log.Errorf("failed creating connection to Management Service %v", err)
		return nil, err
	}

	realClient := proto.NewManagementServiceClient(conn)

	return &GrpcClient{
		key:        ourPrivateKey,
		realClient: realClient,
		ctx:        ctx,
		conn:       conn,
	}, nil
}

// Close closes connection to the Management Service
func (c *GrpcClient) Close() error {
	return c.conn.Close()
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

// ready indicates whether the client is okay and ready to be used
// for now it just checks whether gRPC connection to the service is ready
func (c *GrpcClient) ready() bool {
	return c.conn.GetState() == connectivity.Ready || c.conn.GetState() == connectivity.Idle
}

// Sync wraps the real client's Sync endpoint call and takes care of retries and encryption/decryption of messages
// Blocking request. The result will be sent via msgHandler callback function
func (c *GrpcClient) Sync(msgHandler func(msg *proto.SyncResponse) error) error {

	var backOff = defaultBackoff(c.ctx)

	operation := func() error {

		log.Debugf("management connection state %v", c.conn.GetState())

		if !c.ready() {
			return fmt.Errorf("no connection to management")
		}

		// todo we already have it since we did the Login, maybe cache it locally?
		serverPubKey, err := c.GetServerPublicKey()
		if err != nil {
			log.Errorf("failed getting Management Service public key: %s", err)
			return err
		}

		stream, err := c.connectToStream(*serverPubKey)
		if err != nil {
			log.Errorf("failed to open Management Service stream: %s", err)
			return err
		}

		log.Infof("connected to the Management Service stream")

		// blocking until error
		err = c.receiveEvents(stream, *serverPubKey, msgHandler)
		if err != nil {
			backOff.Reset()
			return err
		}

		return nil
	}

	err := backoff.Retry(operation, backOff)
	if err != nil {
		log.Warnf("exiting Management Service connection retry loop due to unrecoverable error: %s", err)
		return err
	}

	return nil
}

func (c *GrpcClient) connectToStream(serverPubKey wgtypes.Key) (proto.ManagementService_SyncClient, error) {
	req := &proto.SyncRequest{}

	myPrivateKey := c.key
	myPublicKey := myPrivateKey.PublicKey()

	encryptedReq, err := encryption.EncryptMessage(serverPubKey, myPrivateKey, req)
	if err != nil {
		log.Errorf("failed encrypting message: %s", err)
		return nil, err
	}

	syncReq := &proto.EncryptedMessage{WgPubKey: myPublicKey.String(), Body: encryptedReq}
	return c.realClient.Sync(c.ctx, syncReq)
}

func (c *GrpcClient) receiveEvents(stream proto.ManagementService_SyncClient, serverPubKey wgtypes.Key, msgHandler func(msg *proto.SyncResponse) error) error {
	for {
		update, err := stream.Recv()
		if err == io.EOF {
			log.Errorf("Management stream has been closed by server: %s", err)
			return err
		}
		if err != nil {
			log.Warnf("disconnected from Management Service sync stream: %v", err)
			return err
		}

		log.Debugf("got an update message from Management Service")
		decryptedResp := &proto.SyncResponse{}
		err = encryption.DecryptMessage(serverPubKey, c.key, update.Body, decryptedResp)
		if err != nil {
			log.Errorf("failed decrypting update message from Management Service: %s", err)
			return err
		}

		err = msgHandler(decryptedResp)
		if err != nil {
			log.Errorf("failed handling an update message received from Management Service: %v", err.Error())
			return err
		}
	}
}

// GetServerPublicKey returns server Wireguard public key (used later for encrypting messages sent to the server)
func (c *GrpcClient) GetServerPublicKey() (*wgtypes.Key, error) {
	if !c.ready() {
		return nil, fmt.Errorf("no connection to management")
	}

	mgmCtx, cancel := context.WithTimeout(c.ctx, 5*time.Second) //todo make a general setting
	defer cancel()
	resp, err := c.realClient.GetServerKey(mgmCtx, &proto.Empty{})
	if err != nil {
		return nil, err
	}

	serverKey, err := wgtypes.ParseKey(resp.Key)
	if err != nil {
		return nil, err
	}

	return &serverKey, nil
}

func (c *GrpcClient) login(serverKey wgtypes.Key, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	if !c.ready() {
		return nil, fmt.Errorf("no connection to management")
	}
	loginReq, err := encryption.EncryptMessage(serverKey, c.key, req)
	if err != nil {
		log.Errorf("failed to encrypt message: %s", err)
		return nil, err
	}
	mgmCtx, cancel := context.WithTimeout(c.ctx, 5*time.Second) //todo make a general setting
	defer cancel()
	resp, err := c.realClient.Login(mgmCtx, &proto.EncryptedMessage{
		WgPubKey: c.key.PublicKey().String(),
		Body:     loginReq,
	})

	if err != nil {
		return nil, err
	}

	loginResp := &proto.LoginResponse{}
	err = encryption.DecryptMessage(serverKey, c.key, resp.Body, loginResp)
	if err != nil {
		log.Errorf("failed to decrypt registration message: %s", err)
		return nil, err
	}

	return loginResp, nil
}

// Register registers peer on Management Server. It actually calls a Login endpoint with a provided setup key
// Takes care of encrypting and decrypting messages.
// This method will also collect system info and send it with the request (e.g. hostname, os, etc)
func (c *GrpcClient) Register(serverKey wgtypes.Key, setupKey string) (*proto.LoginResponse, error) {
	gi := system.GetInfo()
	meta := &proto.PeerSystemMeta{
		Hostname:           gi.Hostname,
		GoOS:               gi.GoOS,
		OS:                 gi.OS,
		Core:               gi.OSVersion,
		Platform:           gi.Platform,
		Kernel:             gi.Kernel,
		WiretrusteeVersion: "",
	}
	log.Debugf("detected system %v", meta)
	return c.login(serverKey, &proto.LoginRequest{SetupKey: setupKey, Meta: meta})
}

// Login attempts login to Management Server. Takes care of encrypting and decrypting messages.
func (c *GrpcClient) Login(serverKey wgtypes.Key) (*proto.LoginResponse, error) {
	return c.login(serverKey, &proto.LoginRequest{})
}
