package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
	nbgrpc "github.com/netbirdio/netbird/util/grpc"
)

const ConnectTimeout = 10 * time.Second

const (
	errMsgMgmtPublicKey    = "failed getting Management Service public key: %s"
	errMsgNoMgmtConnection = "no connection to management"
)

// ConnStateNotifier is a wrapper interface of the status recorders
type ConnStateNotifier interface {
	MarkManagementDisconnected(error)
	MarkManagementConnected()
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
	var conn *grpc.ClientConn

	operation := func() error {
		var err error
		conn, err = nbgrpc.CreateConnection(addr, tlsEnabled)
		if err != nil {
			log.Printf("createConnection error: %v", err)
			return err
		}
		return nil
	}

	err := backoff.Retry(operation, nbgrpc.Backoff(ctx))
	if err != nil {
		log.Errorf("failed creating connection to Management Service: %v", err)
		return nil, err
	}

	realClient := proto.NewManagementServiceClient(conn)

	return &GrpcClient{
		key:                   ourPrivateKey,
		realClient:            realClient,
		ctx:                   ctx,
		conn:                  conn,
		connStateCallbackLock: sync.RWMutex{},
	}, nil
}

// Close closes connection to the Management Service
func (c *GrpcClient) Close() error {
	return c.conn.Close()
}

// SetConnStateListener set the ConnStateNotifier
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
func (c *GrpcClient) Sync(ctx context.Context, sysInfo *system.Info, msgHandler func(msg *proto.SyncResponse) error) error {
	return c.withMgmtStream(ctx, func(ctx context.Context, serverPubKey wgtypes.Key) error {
		return c.handleSyncStream(ctx, serverPubKey, sysInfo, msgHandler)
	})
}

// Job wraps the real client's Job endpoint call and takes care of retries and encryption/decryption of messages
// Blocking request. The result will be sent via msgHandler callback function
func (c *GrpcClient) Job(ctx context.Context, msgHandler func(msg *proto.JobRequest) error) error {
	return c.withMgmtStream(ctx, func(ctx context.Context, serverPubKey wgtypes.Key) error {
		return c.handleJobStream(ctx, serverPubKey, msgHandler)
	})
}

// withMgmtStream runs a streaming operation against the ManagementService
// It takes care of retries, connection readiness, and fetching server public key.
func (c *GrpcClient) withMgmtStream(
	ctx context.Context,
	handler func(ctx context.Context, serverPubKey wgtypes.Key) error,
) error {
	operation := func() error {
		log.Debugf("management connection state %v", c.conn.GetState())
		connState := c.conn.GetState()

		if connState == connectivity.Shutdown {
			return backoff.Permanent(fmt.Errorf("connection to management has been shut down"))
		} else if !(connState == connectivity.Ready || connState == connectivity.Idle) {
			c.conn.WaitForStateChange(ctx, connState)
			return fmt.Errorf("connection to management is not ready and in %s state", connState)
		}

		serverPubKey, err := c.GetServerPublicKey()
		if err != nil {
			log.Debugf(errMsgMgmtPublicKey, err)
			return err
		}

		return handler(ctx, *serverPubKey)
	}

	err := backoff.Retry(operation, defaultBackoff(ctx))
	if err != nil {
		log.Warnf("exiting the Management service connection retry loop due to the unrecoverable error: %s", err)
	}

	return err
}

func (c *GrpcClient) handleJobStream(ctx context.Context, serverPubKey wgtypes.Key, msgHandler func(msg *proto.JobRequest) error) error {
	ctx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	stream, err := c.connectToJobStream(ctx, serverPubKey)
	if err != nil {
		log.Debugf("failed to open Management Job stream: %s", err)
		if s, ok := gstatus.FromError(err); ok && s.Code() == codes.PermissionDenied {
			return backoff.Permanent(err) // unrecoverable
		}
		return err
	}

	log.Infof("connected to the Management Service stream")
	c.notifyConnected()

	// blocking until error
	err = c.receiveJobEvents(stream, serverPubKey, msgHandler)
	if err != nil {
		c.notifyDisconnected(err)
		s, _ := gstatus.FromError(err)
		switch s.Code() {
		case codes.PermissionDenied:
			return backoff.Permanent(err) // unrecoverable error, propagate to the upper layer
		case codes.Canceled:
			log.Debugf("management connection context has been canceled, this usually indicates shutdown")
			return nil
		default:
			log.Warnf("disconnected from the Management service but will retry silently. Reason: %v", err)
			return err
		}
	}

	return nil
}

func (c *GrpcClient) handleSyncStream(ctx context.Context, serverPubKey wgtypes.Key, sysInfo *system.Info, msgHandler func(msg *proto.SyncResponse) error) error {
	ctx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	stream, err := c.connectToStream(ctx, serverPubKey, sysInfo)
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
	err = c.receiveUpdatesEvents(stream, serverPubKey, msgHandler)
	if err != nil {
		c.notifyDisconnected(err)
		s, _ := gstatus.FromError(err)
		switch s.Code() {
		case codes.PermissionDenied:
			return backoff.Permanent(err) // unrecoverable error, propagate to the upper layer
		case codes.Canceled:
			log.Debugf("management connection context has been canceled, this usually indicates shutdown")
			return nil
		default:
			log.Warnf("disconnected from the Management service but will retry silently. Reason: %v", err)
			return err
		}
	}

	return nil
}

// GetNetworkMap return with the network map
func (c *GrpcClient) GetNetworkMap(sysInfo *system.Info) (*proto.NetworkMap, error) {
	serverPubKey, err := c.GetServerPublicKey()
	if err != nil {
		log.Debugf("failed getting Management Service public key: %s", err)
		return nil, err
	}

	ctx, cancelStream := context.WithCancel(c.ctx)
	defer cancelStream()
	stream, err := c.connectToStream(ctx, *serverPubKey, sysInfo)
	if err != nil {
		log.Debugf("failed to open Management Service stream: %s", err)
		return nil, err
	}
	defer func() {
		_ = stream.CloseSend()
	}()

	update, err := stream.Recv()
	if err == io.EOF {
		log.Debugf("Management stream has been closed by server: %s", err)
		return nil, err
	}
	if err != nil {
		log.Debugf("disconnected from Management Service sync stream: %v", err)
		return nil, err
	}

	decryptedResp := &proto.SyncResponse{}
	err = encryption.DecryptMessage(*serverPubKey, c.key, update.Body, decryptedResp)
	if err != nil {
		log.Errorf("failed decrypting update message from Management Service: %s", err)
		return nil, err
	}

	if decryptedResp.GetNetworkMap() == nil {
		return nil, fmt.Errorf("invalid msg, required network map")
	}

	return decryptedResp.GetNetworkMap(), nil
}

func (c *GrpcClient) connectToJobStream(ctx context.Context, serverPubKey wgtypes.Key) (proto.ManagementService_JobClient, error) {
	req := &proto.JobRequest{}

	myPrivateKey := c.key
	myPublicKey := myPrivateKey.PublicKey()

	encryptedReq, err := encryption.EncryptMessage(serverPubKey, myPrivateKey, req)
	if err != nil {
		return nil, fmt.Errorf("encrypt job hello: %w", err)
	}
	jobReq := &proto.EncryptedMessage{WgPubKey: myPublicKey.String(), Body: encryptedReq}
	job, err := c.realClient.Job(ctx, jobReq)
	if err != nil {
		return nil, err
	}
	return job, nil
}

func (c *GrpcClient) connectToStream(ctx context.Context, serverPubKey wgtypes.Key, sysInfo *system.Info) (proto.ManagementService_SyncClient, error) {
	req := &proto.SyncRequest{Meta: infoToMetaData(sysInfo)}

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

func (c *GrpcClient) receiveJobEvents(stream proto.ManagementService_JobClient, serverPubKey wgtypes.Key, msgHandler func(msg *proto.JobRequest) error) error {
	for {
		enc, err := stream.Recv()
		if err == io.EOF {
			log.Debugf("Management stream has been closed by server: %s", err)
			return err
		}
		if err != nil {
			log.Debugf("disconnected from Management Service sync stream: %v", err)
			return err
		}

		log.Debugf("got an jobs message from Management Service")
		req := &proto.JobRequest{}
		if err := encryption.DecryptMessage(serverPubKey, c.key, enc.Body, req); err != nil {
			log.Errorf("failed decrypting Job message: %s", err)
			return err
		}

		if err := msgHandler(req); err != nil {
			log.Errorf("failed handling an update message received from Management Service: %v", err.Error())
		}
	}
}

func (c *GrpcClient) receiveUpdatesEvents(stream proto.ManagementService_SyncClient, serverPubKey wgtypes.Key, msgHandler func(msg *proto.SyncResponse) error) error {
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

		if err := msgHandler(decryptedResp); err != nil {
			log.Errorf("failed handling an update message received from Management Service: %v", err.Error())
		}
	}
}

// GetServerPublicKey returns server's WireGuard public key (used later for encrypting messages sent to the server)
func (c *GrpcClient) GetServerPublicKey() (*wgtypes.Key, error) {
	if !c.ready() {
		return nil, errors.New(errMsgNoMgmtConnection)
	}

	mgmCtx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	resp, err := c.realClient.GetServerKey(mgmCtx, &proto.Empty{})
	if err != nil {
		log.Errorf("failed while getting Management Service public key: %v", err)
		return nil, fmt.Errorf("failed while getting Management Service public key")
	}

	serverKey, err := wgtypes.ParseKey(resp.Key)
	if err != nil {
		return nil, err
	}

	return &serverKey, nil
}

// IsHealthy probes the gRPC connection and returns false on errors
func (c *GrpcClient) IsHealthy() bool {
	switch c.conn.GetState() {
	case connectivity.TransientFailure:
		return false
	case connectivity.Connecting:
		return true
	case connectivity.Shutdown:
		return true
	case connectivity.Idle:
	case connectivity.Ready:
	}

	ctx, cancel := context.WithTimeout(c.ctx, 1*time.Second)
	defer cancel()

	_, err := c.realClient.GetServerKey(ctx, &proto.Empty{})
	if err != nil {
		c.notifyDisconnected(err)
		log.Warnf("health check returned: %s", err)
		return false
	}
	c.notifyConnected()
	return true
}

func (c *GrpcClient) login(serverKey wgtypes.Key, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	if !c.ready() {
		return nil, errors.New(errMsgNoMgmtConnection)
	}

	loginReq, err := encryption.EncryptMessage(serverKey, c.key, req)
	if err != nil {
		log.Errorf("failed to encrypt message: %s", err)
		return nil, err
	}

	var resp *proto.EncryptedMessage
	operation := func() error {
		mgmCtx, cancel := context.WithTimeout(context.Background(), ConnectTimeout)
		defer cancel()

		var err error
		resp, err = c.realClient.Login(mgmCtx, &proto.EncryptedMessage{
			WgPubKey: c.key.PublicKey().String(),
			Body:     loginReq,
		})
		if err != nil {
			// retry only on context canceled
			if s, ok := gstatus.FromError(err); ok && s.Code() == codes.Canceled {
				return err
			}
			return backoff.Permanent(err)
		}

		return nil
	}

	err = backoff.Retry(operation, nbgrpc.Backoff(c.ctx))
	if err != nil {
		log.Errorf("failed to login to Management Service: %v", err)
		return nil, err
	}

	loginResp := &proto.LoginResponse{}
	err = encryption.DecryptMessage(serverKey, c.key, resp.Body, loginResp)
	if err != nil {
		log.Errorf("failed to decrypt login response: %s", err)
		return nil, err
	}

	return loginResp, nil
}

// Register registers peer on Management Server. It actually calls a Login endpoint with a provided setup key
// Takes care of encrypting and decrypting messages.
// This method will also collect system info and send it with the request (e.g. hostname, os, etc)
func (c *GrpcClient) Register(serverKey wgtypes.Key, setupKey string, jwtToken string, sysInfo *system.Info, pubSSHKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error) {
	keys := &proto.PeerKeys{
		SshPubKey: pubSSHKey,
		WgPubKey:  []byte(c.key.PublicKey().String()),
	}
	return c.login(serverKey, &proto.LoginRequest{SetupKey: setupKey, Meta: infoToMetaData(sysInfo), JwtToken: jwtToken, PeerKeys: keys, DnsLabels: dnsLabels.ToPunycodeList()})
}

// Login attempts login to Management Server. Takes care of encrypting and decrypting messages.
func (c *GrpcClient) Login(serverKey wgtypes.Key, sysInfo *system.Info, pubSSHKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error) {
	keys := &proto.PeerKeys{
		SshPubKey: pubSSHKey,
		WgPubKey:  []byte(c.key.PublicKey().String()),
	}
	return c.login(serverKey, &proto.LoginRequest{Meta: infoToMetaData(sysInfo), PeerKeys: keys, DnsLabels: dnsLabels.ToPunycodeList()})
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

// GetPKCEAuthorizationFlow returns a pkce authorization flow information.
// It also takes care of encrypting and decrypting messages.
func (c *GrpcClient) GetPKCEAuthorizationFlow(serverKey wgtypes.Key) (*proto.PKCEAuthorizationFlow, error) {
	if !c.ready() {
		return nil, fmt.Errorf("no connection to management in order to get pkce authorization flow")
	}
	mgmCtx, cancel := context.WithTimeout(c.ctx, time.Second*2)
	defer cancel()

	message := &proto.PKCEAuthorizationFlowRequest{}
	encryptedMSG, err := encryption.EncryptMessage(serverKey, c.key, message)
	if err != nil {
		return nil, err
	}

	resp, err := c.realClient.GetPKCEAuthorizationFlow(mgmCtx, &proto.EncryptedMessage{
		WgPubKey: c.key.PublicKey().String(),
		Body:     encryptedMSG,
	})
	if err != nil {
		return nil, err
	}

	flowInfoResp := &proto.PKCEAuthorizationFlow{}
	err = encryption.DecryptMessage(serverKey, c.key, resp.Body, flowInfoResp)
	if err != nil {
		errWithMSG := fmt.Errorf("failed to decrypt pkce authorization flow message: %s", err)
		log.Error(errWithMSG)
		return nil, errWithMSG
	}

	return flowInfoResp, nil
}

// SyncMeta sends updated system metadata to the Management Service.
// It should be used if there is changes on peer posture check after initial sync.
func (c *GrpcClient) SyncMeta(sysInfo *system.Info) error {
	if !c.ready() {
		return errors.New(errMsgNoMgmtConnection)
	}

	serverPubKey, err := c.GetServerPublicKey()
	if err != nil {
		log.Debugf(errMsgMgmtPublicKey, err)
		return err
	}

	syncMetaReq, err := encryption.EncryptMessage(*serverPubKey, c.key, &proto.SyncMetaRequest{Meta: infoToMetaData(sysInfo)})
	if err != nil {
		log.Errorf("failed to encrypt message: %s", err)
		return err
	}

	mgmCtx, cancel := context.WithTimeout(c.ctx, ConnectTimeout)
	defer cancel()

	_, err = c.realClient.SyncMeta(mgmCtx, &proto.EncryptedMessage{
		WgPubKey: c.key.PublicKey().String(),
		Body:     syncMetaReq,
	})
	return err
}

func (c *GrpcClient) notifyDisconnected(err error) {
	c.connStateCallbackLock.RLock()
	defer c.connStateCallbackLock.RUnlock()

	if c.connStateCallback == nil {
		return
	}
	c.connStateCallback.MarkManagementDisconnected(err)
}

func (c *GrpcClient) notifyConnected() {
	c.connStateCallbackLock.RLock()
	defer c.connStateCallbackLock.RUnlock()

	if c.connStateCallback == nil {
		return
	}
	c.connStateCallback.MarkManagementConnected()
}

func (c *GrpcClient) Logout() error {
	serverKey, err := c.GetServerPublicKey()
	if err != nil {
		return fmt.Errorf("get server public key: %w", err)
	}

	mgmCtx, cancel := context.WithTimeout(c.ctx, time.Second*15)
	defer cancel()

	message := &proto.Empty{}
	encryptedMSG, err := encryption.EncryptMessage(*serverKey, c.key, message)
	if err != nil {
		return fmt.Errorf("encrypt logout message: %w", err)
	}

	_, err = c.realClient.Logout(mgmCtx, &proto.EncryptedMessage{
		WgPubKey: c.key.PublicKey().String(),
		Body:     encryptedMSG,
	})
	if err != nil {
		return fmt.Errorf("logout: %w", err)
	}

	return nil
}

func infoToMetaData(info *system.Info) *proto.PeerSystemMeta {
	if info == nil {
		return nil
	}

	addresses := make([]*proto.NetworkAddress, 0, len(info.NetworkAddresses))
	for _, addr := range info.NetworkAddresses {
		addresses = append(addresses, &proto.NetworkAddress{
			NetIP: addr.NetIP.String(),
			Mac:   addr.Mac,
		})
	}

	files := make([]*proto.File, 0, len(info.Files))
	for _, file := range info.Files {
		files = append(files, &proto.File{
			Path:             file.Path,
			Exist:            file.Exist,
			ProcessIsRunning: file.ProcessIsRunning,
		})
	}

	return &proto.PeerSystemMeta{
		Hostname:         info.Hostname,
		GoOS:             info.GoOS,
		OS:               info.OS,
		Core:             info.OSVersion,
		OSVersion:        info.OSVersion,
		Platform:         info.Platform,
		Kernel:           info.Kernel,
		NetbirdVersion:   info.NetbirdVersion,
		UiVersion:        info.UIVersion,
		KernelVersion:    info.KernelVersion,
		NetworkAddresses: addresses,
		SysSerialNumber:  info.SystemSerialNumber,
		SysManufacturer:  info.SystemManufacturer,
		SysProductName:   info.SystemProductName,
		Environment: &proto.Environment{
			Cloud:    info.Environment.Cloud,
			Platform: info.Environment.Platform,
		},
		Files: files,

		Flags: &proto.Flags{
			RosenpassEnabled:    info.RosenpassEnabled,
			RosenpassPermissive: info.RosenpassPermissive,
			ServerSSHAllowed:    info.ServerSSHAllowed,

			DisableClientRoutes: info.DisableClientRoutes,
			DisableServerRoutes: info.DisableServerRoutes,
			DisableDNS:          info.DisableDNS,
			DisableFirewall:     info.DisableFirewall,
			BlockLANAccess:      info.BlockLANAccess,
			BlockInbound:        info.BlockInbound,

			LazyConnectionEnabled: info.LazyConnectionEnabled,
		},
	}
}
