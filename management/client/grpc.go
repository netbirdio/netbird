package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/cenkalti/backoff/v4"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/proto"
)

type ConnStateNotifier interface {
	MarkManagementDisconnected(signalURL string)
	MarkManagementConnected(signalURL string)
}

type GrpcClient struct {
	key                   wgtypes.Key
	realClient            proto.ManagementServiceClient
	ctx                   context.Context
	conn                  *grpc.ClientConn
	connStateCallback     ConnStateNotifier
	connStateCallbackLock sync.RWMutex
}

// NewClient creates a new client to Management service
func NewClient(ctx context.Context, addr string, ourPrivateKey wgtypes.Key, tlsEnabled bool) (*GrpcClient, error) {
	transportOption := grpc.WithTransportCredentials(insecure.NewCredentials())

	if tlsEnabled {
		transportOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
	}

	mgmCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
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

func (c *GrpcClient) SetConnStateListener(notifier ConnStateNotifier) {
	c.connStateCallbackLock.Lock()
	defer c.connStateCallbackLock.Unlock()
	c.connStateCallback = notifier
}

// defaultBackoff is a basic backoff mechanism for general issues
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

// ready indicates whether the client is okay and ready to be used
// for now it just checks whether gRPC connection to the service is ready
func (c *GrpcClient) ready() bool {
	return c.conn.GetState() == connectivity.Ready || c.conn.GetState() == connectivity.Idle
}

// Sync wraps the real client's Sync endpoint call and takes care of retries and encryption/decryption of messages
// Blocking request. The result will be sent via msgHandler callback function
func (c *GrpcClient) Sync(msgHandler func(msg *proto.SyncResponse) error) error {
	backOff := defaultBackoff(c.ctx)

	operation := func() error {
		log.Debugf("management connection state %v", c.conn.GetState())

		connState := c.conn.GetState()
		if connState == connectivity.Shutdown {
			return backoff.Permanent(fmt.Errorf("connection to management has been shut down"))
		} else if !(connState == connectivity.Ready || connState == connectivity.Idle) {
			c.conn.WaitForStateChange(c.ctx, connState)
			return fmt.Errorf("connection to management is not ready and in %s state", connState)
		}

		serverPubKey, err := c.GetServerPublicKey()
		if err != nil {
			log.Debugf("failed getting Management Service public key: %s", err)
			return err
		}

		ctx, cancelStream := context.WithCancel(c.ctx)
		defer cancelStream()
		stream, err := c.connectToStream(ctx, *serverPubKey)
		if err != nil {
			log.Debugf("failed to open Management Service stream: %s", err)
			if s, ok := gstatus.FromError(err); ok && s.Code() == codes.PermissionDenied {
				return backoff.Permanent(err) // unrecoverable error, propagate to the upper layer
			}
			return err
		}

		log.Infof("connected to the Management Service stream")
		c.notifyConnected()
		// blocking until error
		err = c.receiveEvents(stream, *serverPubKey, msgHandler)
		if err != nil {
			if s, ok := gstatus.FromError(err); ok && s.Code() == codes.PermissionDenied {
				return backoff.Permanent(err) // unrecoverable error, propagate to the upper layer
			}
			// we need this reset because after a successful connection and a consequent error, backoff lib doesn't
			// reset times and next try will start with a long delay
			backOff.Reset()
			c.notifyDisconnected()
			log.Warnf("disconnected from the Management service but will retry silently. Reason: %v", err)
			return err
		}

		return nil
	}

	err := backoff.Retry(operation, backOff)
	if err != nil {
		log.Warnf("exiting the Management service connection retry loop due to the unrecoverable error: %s", err)
		return err
	}

	return nil
}

func (c *GrpcClient) connectToStream(ctx context.Context, serverPubKey wgtypes.Key) (proto.ManagementService_SyncClient, error) {
	req := &proto.SyncRequest{}

	myPrivateKey := c.key
	myPublicKey := myPrivateKey.PublicKey()

	encryptedReq, err := encryption.EncryptMessage(serverPubKey, myPrivateKey, req)
	if err != nil {
		log.Errorf("failed encrypting message: %s", err)
		return nil, err
	}
	syncReq := &proto.EncryptedMessage{WgPubKey: myPublicKey.String(), Body: encryptedReq}
	sync, err := c.realClient.Sync(ctx, syncReq)
	if err != nil {
		return nil, err
	}
	return sync, nil
}

func (c *GrpcClient) receiveEvents(stream proto.ManagementService_SyncClient, serverPubKey wgtypes.Key, msgHandler func(msg *proto.SyncResponse) error) error {
	for {
		update, err := stream.Recv()
		if err == io.EOF {
			log.Debugf("Management stream has been closed by server: %s", err)
			return err
		}
		if err != nil {
			log.Debugf("disconnected from Management Service sync stream: %v", err)
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

// GetServerPublicKey returns server's WireGuard public key (used later for encrypting messages sent to the server)
func (c *GrpcClient) GetServerPublicKey() (*wgtypes.Key, error) {
	if !c.ready() {
		return nil, fmt.Errorf("no connection to management")
	}

	mgmCtx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
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
	mgmCtx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
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
func (c *GrpcClient) Register(serverKey wgtypes.Key, setupKey string, jwtToken string, sysInfo *system.Info, pubSSHKey []byte) (*proto.LoginResponse, error) {
	keys := &proto.PeerKeys{
		SshPubKey: pubSSHKey,
		WgPubKey:  []byte(c.key.PublicKey().String()),
	}
	return c.login(serverKey, &proto.LoginRequest{SetupKey: setupKey, Meta: infoToMetaData(sysInfo), JwtToken: jwtToken, PeerKeys: keys})
}

// Login attempts login to Management Server. Takes care of encrypting and decrypting messages.
func (c *GrpcClient) Login(serverKey wgtypes.Key, sysInfo *system.Info, pubSSHKey []byte) (*proto.LoginResponse, error) {
	keys := &proto.PeerKeys{
		SshPubKey: pubSSHKey,
		WgPubKey:  []byte(c.key.PublicKey().String()),
	}
	return c.login(serverKey, &proto.LoginRequest{Meta: infoToMetaData(sysInfo), PeerKeys: keys})
}

// GetDeviceAuthorizationFlow returns a device authorization flow information.
// It also takes care of encrypting and decrypting messages.
func (c *GrpcClient) GetDeviceAuthorizationFlow(serverKey wgtypes.Key) (*proto.DeviceAuthorizationFlow, error) {
	if !c.ready() {
		return nil, fmt.Errorf("no connection to management in order to get device authorization flow")
	}
	mgmCtx, cancel := context.WithTimeout(c.ctx, time.Second*2)
	defer cancel()

	message := &proto.DeviceAuthorizationFlowRequest{}
	encryptedMSG, err := encryption.EncryptMessage(serverKey, c.key, message)
	if err != nil {
		return nil, err
	}

	resp, err := c.realClient.GetDeviceAuthorizationFlow(mgmCtx, &proto.EncryptedMessage{
		WgPubKey: c.key.PublicKey().String(),
		Body:     encryptedMSG},
	)
	if err != nil {
		return nil, err
	}

	flowInfoResp := &proto.DeviceAuthorizationFlow{}
	err = encryption.DecryptMessage(serverKey, c.key, resp.Body, flowInfoResp)
	if err != nil {
		errWithMSG := fmt.Errorf("failed to decrypt device authorization flow message: %s", err)
		log.Error(errWithMSG)
		return nil, errWithMSG
	}

	return flowInfoResp, nil
}

func (c *GrpcClient) notifyDisconnected() {
	c.connStateCallbackLock.RLock()
	defer c.connStateCallbackLock.RUnlock()

	if c.connStateCallback == nil {
		return
	}
	c.connStateCallback.MarkManagementConnected(c.conn.Target())
}

func (c *GrpcClient) notifyConnected() {
	c.connStateCallbackLock.RLock()
	defer c.connStateCallbackLock.RUnlock()

	if c.connStateCallback == nil {
		return
	}
	c.connStateCallback.MarkManagementConnected(c.conn.Target())
}

func infoToMetaData(info *system.Info) *proto.PeerSystemMeta {
	if info == nil {
		return nil
	}
	return &proto.PeerSystemMeta{
		Hostname:           info.Hostname,
		GoOS:               info.GoOS,
		OS:                 info.OS,
		Core:               info.OSVersion,
		Platform:           info.Platform,
		Kernel:             info.Kernel,
		WiretrusteeVersion: info.WiretrusteeVersion,
		UiVersion:          info.UIVersion,
	}
}
