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

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util/wsproxy"
)

// Custom management client errors that abstract away gRPC error codes
var (
	// ErrPermissionDenied is returned when the server denies access to a resource
	ErrPermissionDenied = errors.New("permission denied")

	// ErrInvalidArgument is returned when the request contains invalid arguments
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrUnauthenticated is returned when authentication is required
	ErrUnauthenticated = errors.New("unauthenticated")

	// ErrNotFound is returned when the requested resource is not found
	ErrNotFound = errors.New("not found")

	// ErrUnimplemented is returned when the operation is not implemented
	ErrUnimplemented = errors.New("not implemented")
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
	conn                  *grpc.ClientConn
	connStateCallback     ConnStateNotifier
	connStateCallbackLock sync.RWMutex
	addr                  string
	tlsEnabled            bool
	reconnectMutex        sync.Mutex
}

// NewClient creates a new client to Management service
// The client is not connected after creation - call Connect to establish the connection
func NewClient(addr string, ourPrivateKey wgtypes.Key, tlsEnabled bool) *GrpcClient {
	return &GrpcClient{
		key:                   ourPrivateKey,
		addr:                  addr,
		tlsEnabled:            tlsEnabled,
		connStateCallbackLock: sync.RWMutex{},
		reconnectMutex:        sync.Mutex{},
	}
}

// Connect establishes a connection to the Management Service with retry logic
// Retries connection attempts with exponential backoff on failure
func (c *GrpcClient) Connect(ctx context.Context) error {
	var conn *grpc.ClientConn

	operation := func() error {
		var err error
		conn, err = nbgrpc.CreateConnection(ctx, c.addr, c.tlsEnabled, wsproxy.ManagementComponent)
		if err != nil {
			log.Warnf("failed to connect to Management Service: %v", err)
			return err
		}
		return nil
	}

	if err := backoff.Retry(operation, defaultBackoff(ctx)); err != nil {
		log.Errorf("failed creating connection to Management Service after retries: %v", err)
		return fmt.Errorf("create connection: %w", err)
	}

	c.conn = conn
	c.realClient = proto.NewManagementServiceClient(conn)

	log.Infof("connected to the Management Service at %s", c.addr)
	return nil
}

// ConnectWithoutRetry establishes a connection to the Management Service without retry logic
// Performs a single connection attempt - callers should implement their own retry logic if needed
func (c *GrpcClient) ConnectWithoutRetry(ctx context.Context) error {
	conn, err := nbgrpc.CreateConnection(ctx, c.addr, c.tlsEnabled, wsproxy.ManagementComponent)
	if err != nil {
		log.Warnf("failed to connect to Management Service: %v", err)
		return fmt.Errorf("create connection: %w", err)
	}

	c.conn = conn
	c.realClient = proto.NewManagementServiceClient(conn)

	log.Debugf("connected to the Management Service at %s", c.addr)
	return nil
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

// ready indicates whether the client is okay and ready to be used
// for now it just checks whether gRPC connection to the service is ready
func (c *GrpcClient) ready() bool {
	return c.conn.GetState() == connectivity.Ready || c.conn.GetState() == connectivity.Idle
}

// Sync wraps the real client's Sync endpoint call and takes care of retries and encryption/decryption of messages
// Blocking request. The result will be sent via msgHandler callback function
func (c *GrpcClient) Sync(ctx context.Context, sysInfo *system.Info, msgHandler func(msg *proto.SyncResponse) error) error {
	operation := func() error {
		log.Debugf("management connection state %v", c.conn.GetState())
		connState := c.conn.GetState()

		if connState == connectivity.Shutdown {
			return backoff.Permanent(fmt.Errorf("connection to management has been shut down"))
		} else if !(connState == connectivity.Ready || connState == connectivity.Idle) {
			c.conn.WaitForStateChange(ctx, connState)
			return fmt.Errorf("connection to management is not ready and in %s state", connState)
		}

		serverPubKey, err := c.getServerPublicKey(ctx)
		if err != nil {
			log.Debugf(errMsgMgmtPublicKey, err)
			return err
		}

		return c.handleStream(ctx, *serverPubKey, sysInfo, msgHandler)
	}

	err := backoff.Retry(operation, defaultBackoff(ctx))
	if err != nil {
		log.Warnf("exiting the Management service connection retry loop due to the unrecoverable error: %s", err)
	}

	return err
}

func (c *GrpcClient) handleStream(ctx context.Context, serverPubKey wgtypes.Key, sysInfo *system.Info,
	msgHandler func(msg *proto.SyncResponse) error) error {
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
	err = c.receiveEvents(stream, serverPubKey, msgHandler)
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
func (c *GrpcClient) GetNetworkMap(ctx context.Context, sysInfo *system.Info) (*proto.NetworkMap, error) {
	serverPubKey, err := c.getServerPublicKey(ctx)
	if err != nil {
		log.Debugf("failed getting Management Service public key: %s", err)
		return nil, err
	}

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

		if err := msgHandler(decryptedResp); err != nil {
			log.Errorf("failed handling an update message received from Management Service: %v", err.Error())
		}
	}
}

// getServerPublicKey returns server's WireGuard public key (used later for encrypting messages sent to the server)
// This is a simple operation without retry logic - callers should handle retries at the operation level
func (c *GrpcClient) getServerPublicKey(ctx context.Context) (*wgtypes.Key, error) {
	if !c.ready() {
		return nil, errors.New(errMsgNoMgmtConnection)
	}

	mgmCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.realClient.GetServerKey(mgmCtx, &proto.Empty{})
	if err != nil {
		log.Errorf("failed while getting Management Service public key: %v", err)
		return nil, fmt.Errorf("failed while getting Management Service public key")
	}

	key, err := wgtypes.ParseKey(resp.Key)
	if err != nil {
		return nil, err
	}

	return &key, nil
}

// IsHealthy probes the gRPC connection and returns false on errors
func (c *GrpcClient) IsHealthy(ctx context.Context) bool {
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

	healthCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	_, err := c.realClient.GetServerKey(healthCtx, &proto.Empty{})
	if err != nil {
		c.notifyDisconnected(err)
		log.Warnf("health check returned: %s", err)
		return false
	}
	c.notifyConnected()
	return true
}

// HealthCheck verifies connectivity to the management server
// Returns an error if the server is not reachable
// Internally uses getServerPublicKey to verify the connection
func (c *GrpcClient) HealthCheck(ctx context.Context) error {
	_, err := c.getServerPublicKey(ctx)
	return err
}

func (c *GrpcClient) login(ctx context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	if !c.ready() {
		return nil, errors.New(errMsgNoMgmtConnection)
	}

	serverKey, err := c.getServerPublicKey(ctx)
	if err != nil {
		log.Debugf(errMsgMgmtPublicKey, err)
		return nil, err
	}

	loginReq, err := encryption.EncryptMessage(*serverKey, c.key, req)
	if err != nil {
		log.Errorf("failed to encrypt message: %s", err)
		return nil, err
	}

	var resp *proto.EncryptedMessage
	operation := func() error {
		mgmCtx, cancel := context.WithTimeout(ctx, ConnectTimeout)
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

	err = backoff.Retry(operation, nbgrpc.Backoff(ctx))
	if err != nil {
		log.Errorf("failed to login to Management Service: %v", err)
		return nil, err
	}

	loginResp := &proto.LoginResponse{}
	err = encryption.DecryptMessage(*serverKey, c.key, resp.Body, loginResp)
	if err != nil {
		log.Errorf("failed to decrypt login response: %s", err)
		return nil, err
	}

	return loginResp, nil
}

// Register registers peer on Management Server. It actually calls a Login endpoint with a provided setup key
// Takes care of encrypting and decrypting messages.
// This method will also collect system info and send it with the request (e.g. hostname, os, etc)
// Returns custom errors: ErrPermissionDenied, ErrInvalidArgument, ErrUnauthenticated
func (c *GrpcClient) Register(ctx context.Context, setupKey string, jwtToken string, sysInfo *system.Info, pubSSHKey []byte, dnsLabels domain.List) error {
	keys := &proto.PeerKeys{
		SshPubKey: pubSSHKey,
		WgPubKey:  []byte(c.key.PublicKey().String()),
	}
	_, err := c.login(ctx, &proto.LoginRequest{SetupKey: setupKey, Meta: infoToMetaData(sysInfo), JwtToken: jwtToken, PeerKeys: keys, DnsLabels: dnsLabels.ToPunycodeList()})
	return wrapGRPCError(err)
}

// Login attempts login to Management Server. Takes care of encrypting and decrypting messages.
// Returns custom errors: ErrPermissionDenied, ErrInvalidArgument, ErrUnauthenticated
func (c *GrpcClient) Login(ctx context.Context, sysInfo *system.Info, pubSSHKey []byte, dnsLabels domain.List) (*proto.LoginResponse, error) {
	keys := &proto.PeerKeys{
		SshPubKey: pubSSHKey,
		WgPubKey:  []byte(c.key.PublicKey().String()),
	}
	resp, err := c.login(ctx, &proto.LoginRequest{Meta: infoToMetaData(sysInfo), PeerKeys: keys, DnsLabels: dnsLabels.ToPunycodeList()})
	return resp, wrapGRPCError(err)
}

// GetDeviceAuthorizationFlow returns a device authorization flow information.
// It also takes care of encrypting and decrypting messages.
// It automatically retries with backoff and reconnection on connection errors.
// Returns custom errors: ErrNotFound, ErrUnimplemented
func (c *GrpcClient) GetDeviceAuthorizationFlow(ctx context.Context) (*proto.DeviceAuthorizationFlow, error) {
	var flowInfoResp *proto.DeviceAuthorizationFlow

	err := c.withRetry(ctx, func() error {
		if !c.ready() {
			return fmt.Errorf("no connection to management in order to get device authorization flow")
		}

		serverKey, err := c.getServerPublicKey(ctx)
		if err != nil {
			log.Debugf(errMsgMgmtPublicKey, err)
			return err
		}

		mgmCtx, cancel := context.WithTimeout(ctx, time.Second*2)
		defer cancel()

		message := &proto.DeviceAuthorizationFlowRequest{}
		encryptedMSG, err := encryption.EncryptMessage(*serverKey, c.key, message)
		if err != nil {
			return err
		}

		resp, err := c.realClient.GetDeviceAuthorizationFlow(mgmCtx, &proto.EncryptedMessage{
			WgPubKey: c.key.PublicKey().String(),
			Body:     encryptedMSG},
		)
		if err != nil {
			return err
		}

		flowInfo := &proto.DeviceAuthorizationFlow{}
		err = encryption.DecryptMessage(*serverKey, c.key, resp.Body, flowInfo)
		if err != nil {
			errWithMSG := fmt.Errorf("failed to decrypt device authorization flow message: %s", err)
			log.Error(errWithMSG)
			return errWithMSG
		}

		flowInfoResp = flowInfo
		return nil
	})

	return flowInfoResp, wrapGRPCError(err)
}

// GetPKCEAuthorizationFlow returns a pkce authorization flow information.
// It also takes care of encrypting and decrypting messages.
// It automatically retries with backoff and reconnection on connection errors.
// Returns custom errors: ErrNotFound, ErrUnimplemented
func (c *GrpcClient) GetPKCEAuthorizationFlow(ctx context.Context) (*proto.PKCEAuthorizationFlow, error) {
	var flowInfoResp *proto.PKCEAuthorizationFlow

	err := c.withRetry(ctx, func() error {
		if !c.ready() {
			return fmt.Errorf("no connection to management in order to get pkce authorization flow")
		}

		serverKey, err := c.getServerPublicKey(ctx)
		if err != nil {
			log.Debugf(errMsgMgmtPublicKey, err)
			return err
		}

		mgmCtx, cancel := context.WithTimeout(ctx, time.Second*2)
		defer cancel()

		message := &proto.PKCEAuthorizationFlowRequest{}
		encryptedMSG, err := encryption.EncryptMessage(*serverKey, c.key, message)
		if err != nil {
			return err
		}

		resp, err := c.realClient.GetPKCEAuthorizationFlow(mgmCtx, &proto.EncryptedMessage{
			WgPubKey: c.key.PublicKey().String(),
			Body:     encryptedMSG,
		})
		if err != nil {
			return err
		}

		flowInfo := &proto.PKCEAuthorizationFlow{}
		err = encryption.DecryptMessage(*serverKey, c.key, resp.Body, flowInfo)
		if err != nil {
			errWithMSG := fmt.Errorf("failed to decrypt pkce authorization flow message: %s", err)
			log.Error(errWithMSG)
			return errWithMSG
		}

		flowInfoResp = flowInfo
		return nil
	})

	return flowInfoResp, wrapGRPCError(err)
}

// SyncMeta sends updated system metadata to the Management Service.
// It should be used if there is changes on peer posture check after initial sync.
func (c *GrpcClient) SyncMeta(ctx context.Context, sysInfo *system.Info) error {
	if !c.ready() {
		return errors.New(errMsgNoMgmtConnection)
	}

	serverPubKey, err := c.getServerPublicKey(ctx)
	if err != nil {
		log.Debugf(errMsgMgmtPublicKey, err)
		return err
	}

	syncMetaReq, err := encryption.EncryptMessage(*serverPubKey, c.key, &proto.SyncMetaRequest{Meta: infoToMetaData(sysInfo)})
	if err != nil {
		log.Errorf("failed to encrypt message: %s", err)
		return err
	}

	mgmCtx, cancel := context.WithTimeout(ctx, ConnectTimeout)
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

func (c *GrpcClient) Logout(ctx context.Context) error {
	serverKey, err := c.getServerPublicKey(ctx)
	if err != nil {
		return fmt.Errorf("get server public key: %w", err)
	}

	mgmCtx, cancel := context.WithTimeout(ctx, time.Second*15)
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

// reconnect closes the current connection and creates a new one
func (c *GrpcClient) reconnect(ctx context.Context) error {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()

	// Close existing connection
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			log.Debugf("error closing old connection: %v", err)
		}
	}

	// Create new connection
	log.Debugf("reconnecting to Management Service %s", c.addr)
	conn, err := nbgrpc.CreateConnection(ctx, c.addr, c.tlsEnabled, wsproxy.ManagementComponent)
	if err != nil {
		log.Errorf("failed reconnecting to Management Service %s: %v", c.addr, err)
		return fmt.Errorf("reconnect: create connection: %w", err)
	}

	c.conn = conn
	c.realClient = proto.NewManagementServiceClient(conn)
	log.Debugf("successfully reconnected to Management service %s", c.addr)
	return nil
}

// withRetry wraps an operation with exponential backoff retry logic
// It automatically reconnects on connection errors
func (c *GrpcClient) withRetry(ctx context.Context, operation func() error) error {
	backoffSettings := &backoff.ExponentialBackOff{
		InitialInterval:     500 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.5,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      2 * time.Minute,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}
	backoffSettings.Reset()

	return backoff.RetryNotify(
		func() error {
			err := operation()
			if err == nil {
				return nil
			}

			// If it's a connection error, attempt reconnection
			if isConnectionError(err) {
				log.Warnf("connection error detected, attempting reconnection: %v", err)
				if reconnectErr := c.reconnect(ctx); reconnectErr != nil {
					log.Errorf("reconnection failed: %v", reconnectErr)
					return reconnectErr
				}
				// Return the original error to trigger retry with the new connection
				return err
			}

			// For authentication errors (InvalidArgument, PermissionDenied), don't retry
			if isAuthenticationError(err) {
				return backoff.Permanent(err)
			}

			return err
		},
		backoff.WithContext(backoffSettings, ctx),
		func(err error, duration time.Duration) {
			log.Warnf("operation failed, retrying in %v: %v", duration, err)
		},
	)
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

// isConnectionError checks if the error is a connection-related error that should trigger reconnection
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	s, ok := gstatus.FromError(err)
	if !ok {
		return false
	}
	// These error codes indicate connection issues
	return s.Code() == codes.Unavailable ||
		s.Code() == codes.DeadlineExceeded ||
		s.Code() == codes.Canceled ||
		s.Code() == codes.Internal
}

// isAuthenticationError checks if the error is an authentication-related error that should not be retried
func isAuthenticationError(err error) bool {
	if err == nil {
		return false
	}
	s, ok := gstatus.FromError(err)
	if !ok {
		return false
	}
	return s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied
}

// wrapGRPCError converts gRPC errors to custom management client errors
func wrapGRPCError(err error) error {
	if err == nil {
		return nil
	}

	// Check if it's already a custom error
	if errors.Is(err, ErrPermissionDenied) ||
		errors.Is(err, ErrInvalidArgument) ||
		errors.Is(err, ErrUnauthenticated) ||
		errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrUnimplemented) {
		return err
	}

	// Convert gRPC status errors to custom errors
	s, ok := gstatus.FromError(err)
	if !ok {
		return err
	}

	switch s.Code() {
	case codes.PermissionDenied:
		return fmt.Errorf("%w: %s", ErrPermissionDenied, s.Message())
	case codes.InvalidArgument:
		return fmt.Errorf("%w: %s", ErrInvalidArgument, s.Message())
	case codes.Unauthenticated:
		return fmt.Errorf("%w: %s", ErrUnauthenticated, s.Message())
	case codes.NotFound:
		return fmt.Errorf("%w: %s", ErrNotFound, s.Message())
	case codes.Unimplemented:
		return fmt.Errorf("%w: %s", ErrUnimplemented, s.Message())
	default:
		return err
	}
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
