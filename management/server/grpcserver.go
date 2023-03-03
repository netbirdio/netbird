package server

import (
	"context"
	"fmt"
	pb "github.com/golang/protobuf/proto" //nolint
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"

	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/netbirdio/netbird/management/server/jwtclaims"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/proto"
	internalStatus "github.com/netbirdio/netbird/management/server/status"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	gRPCPeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// GRPCServer an instance of a Management gRPC API server
type GRPCServer struct {
	accountManager AccountManager
	wgKey          wgtypes.Key
	proto.UnimplementedManagementServiceServer
	peersUpdateManager     *PeersUpdateManager
	config                 *Config
	turnCredentialsManager TURNCredentialsManager
	jwtMiddleware          *middleware.JWTMiddleware
	jwtClaimsExtractor     *jwtclaims.ClaimsExtractor
	appMetrics             telemetry.AppMetrics
}

// NewServer creates a new Management server
func NewServer(config *Config, accountManager AccountManager, peersUpdateManager *PeersUpdateManager,
	turnCredentialsManager TURNCredentialsManager, appMetrics telemetry.AppMetrics,
) (*GRPCServer, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	var jwtMiddleware *middleware.JWTMiddleware

	if config.HttpConfig != nil && config.HttpConfig.AuthIssuer != "" && config.HttpConfig.AuthAudience != "" && validateURL(config.HttpConfig.AuthKeysLocation) {
		jwtMiddleware, err = middleware.NewJwtMiddleware(
			config.HttpConfig.AuthIssuer,
			config.HttpConfig.AuthAudience,
			config.HttpConfig.AuthKeysLocation)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to create new jwt middleware, err: %v", err)
		}
	} else {
		log.Debug("unable to use http config to create new jwt middleware")
	}

	if appMetrics != nil {
		// update gauge based on number of connected peers which is equal to open gRPC streams
		err = appMetrics.GRPCMetrics().RegisterConnectedStreams(func() int64 {
			return int64(len(peersUpdateManager.peerChannels))
		})
		if err != nil {
			return nil, err
		}
	}

	var audience, userIDClaim string
	if config.HttpConfig != nil {
		audience = config.HttpConfig.AuthAudience
		userIDClaim = config.HttpConfig.AuthUserIDClaim
	}
	jwtClaimsExtractor := jwtclaims.NewClaimsExtractor(
		jwtclaims.WithAudience(audience),
		jwtclaims.WithUserIDClaim(userIDClaim),
	)

	return &GRPCServer{
		wgKey: key,
		// peerKey -> event channel
		peersUpdateManager:     peersUpdateManager,
		accountManager:         accountManager,
		config:                 config,
		turnCredentialsManager: turnCredentialsManager,
		jwtMiddleware:          jwtMiddleware,
		jwtClaimsExtractor:     jwtClaimsExtractor,
		appMetrics:             appMetrics,
	}, nil
}

func (s *GRPCServer) GetServerKey(ctx context.Context, req *proto.Empty) (*proto.ServerKeyResponse, error) {
	// todo introduce something more meaningful with the key expiration/rotation
	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountGetKeyRequest()
	}
	now := time.Now().Add(24 * time.Hour)
	secs := int64(now.Second())
	nanos := int32(now.Nanosecond())
	expiresAt := &timestamp.Timestamp{Seconds: secs, Nanos: nanos}

	return &proto.ServerKeyResponse{
		Key:       s.wgKey.PublicKey().String(),
		ExpiresAt: expiresAt,
	}, nil
}

// Sync validates the existence of a connecting peer, sends an initial state (all available for the connecting peers) and
// notifies the connected peer of any updates (e.g. new peers under the same account)
func (s *GRPCServer) Sync(req *proto.EncryptedMessage, srv proto.ManagementService_SyncServer) error {
	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountSyncRequest()
	}
	p, ok := gRPCPeer.FromContext(srv.Context())
	if ok {
		log.Debugf("Sync request from peer [%s] [%s]", req.WgPubKey, p.Addr.String())
	}

	syncReq := &proto.SyncRequest{}
	peerKey, err := s.parseRequest(req, syncReq)
	if err != nil {
		return err
	}

	peer, netMap, err := s.accountManager.SyncPeer(PeerSync{WireGuardPubKey: peerKey.String()})
	if err != nil {
		return mapError(err)
	}

	err = s.sendInitialSync(peerKey, peer, netMap, srv)
	if err != nil {
		log.Debugf("error while sending initial sync for %s: %v", peerKey.String(), err)
		return err
	}

	updates := s.peersUpdateManager.CreateChannel(peer.ID)
	err = s.accountManager.MarkPeerConnected(peerKey.String(), true)
	if err != nil {
		log.Warnf("failed marking peer as connected %s %v", peerKey, err)
	}

	if s.config.TURNConfig.TimeBasedCredentials {
		s.turnCredentialsManager.SetupRefresh(peer.ID)
	}
	// keep a connection to the peer and send updates when available
	for {
		select {
		// condition when there are some updates
		case update, open := <-updates:
			if !open {
				log.Debugf("updates channel for peer %s was closed", peerKey.String())
				s.cancelPeerRoutines(peer)
				return nil
			}
			log.Debugf("recevied an update for peer %s", peerKey.String())

			encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, update.Update)
			if err != nil {
				return status.Errorf(codes.Internal, "failed processing update message")
			}

			err = srv.SendMsg(&proto.EncryptedMessage{
				WgPubKey: s.wgKey.PublicKey().String(),
				Body:     encryptedResp,
			})
			if err != nil {
				return status.Errorf(codes.Internal, "failed sending update message")
			}
			log.Debugf("sent an update to peer %s", peerKey.String())
		// condition when client <-> server connection has been terminated
		case <-srv.Context().Done():
			// happens when connection drops, e.g. client disconnects
			log.Debugf("stream of peer %s has been closed", peerKey.String())
			s.cancelPeerRoutines(peer)
			return srv.Context().Err()
		}
	}
}

func (s *GRPCServer) cancelPeerRoutines(peer *Peer) {
	s.peersUpdateManager.CloseChannel(peer.ID)
	s.turnCredentialsManager.CancelRefresh(peer.ID)
	_ = s.accountManager.MarkPeerConnected(peer.Key, false)
}

func (s *GRPCServer) validateToken(jwtToken string) (string, error) {
	if s.jwtMiddleware == nil {
		return "", status.Error(codes.Internal, "no jwt middleware set")
	}

	token, err := s.jwtMiddleware.ValidateAndParse(jwtToken)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "invalid jwt token, err: %v", err)
	}
	claims := s.jwtClaimsExtractor.FromToken(token)
	// we need to call this method because if user is new, we will automatically add it to existing or create a new account
	_, _, err = s.accountManager.GetAccountFromToken(claims)
	if err != nil {
		return "", status.Errorf(codes.Internal, "unable to fetch account with claims, err: %v", err)
	}

	return claims.UserId, nil
}

// maps internal internalStatus.Error to gRPC status.Error
func mapError(err error) error {
	if e, ok := internalStatus.FromError(err); ok {
		switch e.Type() {
		case internalStatus.PermissionDenied:
			return status.Errorf(codes.PermissionDenied, e.Message)
		case internalStatus.Unauthorized:
			return status.Errorf(codes.PermissionDenied, e.Message)
		case internalStatus.Unauthenticated:
			return status.Errorf(codes.PermissionDenied, e.Message)
		case internalStatus.PreconditionFailed:
			return status.Errorf(codes.FailedPrecondition, e.Message)
		case internalStatus.NotFound:
			return status.Errorf(codes.NotFound, e.Message)
		default:
		}
	}
	return status.Errorf(codes.Internal, "failed handling request")
}

func extractPeerMeta(loginReq *proto.LoginRequest) PeerSystemMeta {
	return PeerSystemMeta{
		Hostname:  loginReq.GetMeta().GetHostname(),
		GoOS:      loginReq.GetMeta().GetGoOS(),
		Kernel:    loginReq.GetMeta().GetKernel(),
		Core:      loginReq.GetMeta().GetCore(),
		Platform:  loginReq.GetMeta().GetPlatform(),
		OS:        loginReq.GetMeta().GetOS(),
		WtVersion: loginReq.GetMeta().GetWiretrusteeVersion(),
		UIVersion: loginReq.GetMeta().GetUiVersion(),
	}
}

func (s *GRPCServer) parseRequest(req *proto.EncryptedMessage, parsed pb.Message) (wgtypes.Key, error) {
	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		log.Warnf("error while parsing peer's WireGuard public key %s.", req.WgPubKey)
		return wgtypes.Key{}, status.Errorf(codes.InvalidArgument, "provided wgPubKey %s is invalid", req.WgPubKey)
	}

	err = encryption.DecryptMessage(peerKey, s.wgKey, req.Body, parsed)
	if err != nil {
		return wgtypes.Key{}, status.Errorf(codes.InvalidArgument, "invalid request message")
	}

	return peerKey, nil
}

// Login endpoint first checks whether peer is registered under any account
// In case it is, the login is successful
// In case it isn't, the endpoint checks whether setup key is provided within the request and tries to register a peer.
// In case of the successful registration login is also successful
func (s *GRPCServer) Login(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountLoginRequest()
	}
	p, ok := gRPCPeer.FromContext(ctx)
	if ok {
		log.Debugf("Login request from peer [%s] [%s]", req.WgPubKey, p.Addr.String())
	}

	loginReq := &proto.LoginRequest{}
	peerKey, err := s.parseRequest(req, loginReq)
	if err != nil {
		return nil, err
	}

	if loginReq.GetMeta() == nil {
		msg := status.Errorf(codes.FailedPrecondition,
			"peer system meta has to be provided to log in. Peer %s, remote addr %s", peerKey.String(),
			p.Addr.String())
		log.Warn(msg)
		return nil, msg
	}

	userID := ""
	// JWT token is not always provided, it is fine for userID to be empty cuz it might be that peer is already registered,
	// or it uses a setup key to register.
	if loginReq.GetJwtToken() != "" {
		userID, err = s.validateToken(loginReq.GetJwtToken())
		if err != nil {
			log.Warnf("failed validating JWT token sent from peer %s", peerKey)
			return nil, mapError(err)
		}
	}
	var sshKey []byte
	if loginReq.GetPeerKeys() != nil {
		sshKey = loginReq.GetPeerKeys().GetSshPubKey()
	}

	peer, netMap, err := s.accountManager.LoginPeer(PeerLogin{
		WireGuardPubKey: peerKey.String(),
		SSHKey:          string(sshKey),
		Meta:            extractPeerMeta(loginReq),
		UserID:          userID,
		SetupKey:        loginReq.GetSetupKey(),
	})
	if err != nil {
		log.Warnf("failed logging in peer %s", peerKey)
		return nil, mapError(err)
	}

	// if peer has reached this point then it has logged in
	loginResp := &proto.LoginResponse{
		WiretrusteeConfig: toWiretrusteeConfig(s.config, nil),
		PeerConfig:        toPeerConfig(peer, netMap.Network, s.accountManager.GetDNSDomain()),
	}
	encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, loginResp)
	if err != nil {
		log.Warnf("failed encrypting peer %s message", peer.ID)
		return nil, status.Errorf(codes.Internal, "failed logging in peer")
	}

	return &proto.EncryptedMessage{
		WgPubKey: s.wgKey.PublicKey().String(),
		Body:     encryptedResp,
	}, nil
}

func ToResponseProto(configProto Protocol) proto.HostConfig_Protocol {
	switch configProto {
	case UDP:
		return proto.HostConfig_UDP
	case DTLS:
		return proto.HostConfig_DTLS
	case HTTP:
		return proto.HostConfig_HTTP
	case HTTPS:
		return proto.HostConfig_HTTPS
	case TCP:
		return proto.HostConfig_TCP
	default:
		panic(fmt.Errorf("unexpected config protocol type %v", configProto))
	}
}

func toWiretrusteeConfig(config *Config, turnCredentials *TURNCredentials) *proto.WiretrusteeConfig {
	if config == nil {
		return nil
	}
	var stuns []*proto.HostConfig
	for _, stun := range config.Stuns {
		stuns = append(stuns, &proto.HostConfig{
			Uri:      stun.URI,
			Protocol: ToResponseProto(stun.Proto),
		})
	}
	var turns []*proto.ProtectedHostConfig
	for _, turn := range config.TURNConfig.Turns {
		var username string
		var password string
		if turnCredentials != nil {
			username = turnCredentials.Username
			password = turnCredentials.Password
		} else {
			username = turn.Username
			password = turn.Password
		}
		turns = append(turns, &proto.ProtectedHostConfig{
			HostConfig: &proto.HostConfig{
				Uri:      turn.URI,
				Protocol: ToResponseProto(turn.Proto),
			},
			User:     username,
			Password: password,
		})
	}

	return &proto.WiretrusteeConfig{
		Stuns: stuns,
		Turns: turns,
		Signal: &proto.HostConfig{
			Uri:      config.Signal.URI,
			Protocol: ToResponseProto(config.Signal.Proto),
		},
	}
}

func toPeerConfig(peer *Peer, network *Network, dnsName string) *proto.PeerConfig {
	netmask, _ := network.Net.Mask.Size()
	fqdn := peer.FQDN(dnsName)
	return &proto.PeerConfig{
		Address:   fmt.Sprintf("%s/%d", peer.IP.String(), netmask), // take it from the network
		SshConfig: &proto.SSHConfig{SshEnabled: peer.SSHEnabled},
		Fqdn:      fqdn,
	}
}

func toRemotePeerConfig(peers []*Peer, dnsName string) []*proto.RemotePeerConfig {
	remotePeers := []*proto.RemotePeerConfig{}
	for _, rPeer := range peers {
		fqdn := rPeer.FQDN(dnsName)
		remotePeers = append(remotePeers, &proto.RemotePeerConfig{
			WgPubKey:   rPeer.Key,
			AllowedIps: []string{fmt.Sprintf(AllowedIPsFormat, rPeer.IP)},
			SshConfig:  &proto.SSHConfig{SshPubKey: []byte(rPeer.SSHKey)},
			Fqdn:       fqdn,
		})
	}
	return remotePeers
}

func toSyncResponse(config *Config, peer *Peer, turnCredentials *TURNCredentials, networkMap *NetworkMap, dnsName string) *proto.SyncResponse {
	wtConfig := toWiretrusteeConfig(config, turnCredentials)

	pConfig := toPeerConfig(peer, networkMap.Network, dnsName)

	remotePeers := toRemotePeerConfig(networkMap.Peers, dnsName)

	routesUpdate := toProtocolRoutes(networkMap.Routes)

	dnsUpdate := toProtocolDNSConfig(networkMap.DNSConfig)

	return &proto.SyncResponse{
		WiretrusteeConfig:  wtConfig,
		PeerConfig:         pConfig,
		RemotePeers:        remotePeers,
		RemotePeersIsEmpty: len(remotePeers) == 0,
		NetworkMap: &proto.NetworkMap{
			Serial:             networkMap.Network.CurrentSerial(),
			PeerConfig:         pConfig,
			RemotePeers:        remotePeers,
			RemotePeersIsEmpty: len(remotePeers) == 0,
			Routes:             routesUpdate,
			DNSConfig:          dnsUpdate,
		},
	}
}

// IsHealthy indicates whether the service is healthy
func (s *GRPCServer) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

// sendInitialSync sends initial proto.SyncResponse to the peer requesting synchronization
func (s *GRPCServer) sendInitialSync(peerKey wgtypes.Key, peer *Peer, networkMap *NetworkMap, srv proto.ManagementService_SyncServer) error {
	// make secret time based TURN credentials optional
	var turnCredentials *TURNCredentials
	if s.config.TURNConfig.TimeBasedCredentials {
		creds := s.turnCredentialsManager.GenerateCredentials()
		turnCredentials = &creds
	} else {
		turnCredentials = nil
	}
	plainResp := toSyncResponse(s.config, peer, turnCredentials, networkMap, s.accountManager.GetDNSDomain())

	encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, plainResp)
	if err != nil {
		return status.Errorf(codes.Internal, "error handling request")
	}

	err = srv.Send(&proto.EncryptedMessage{
		WgPubKey: s.wgKey.PublicKey().String(),
		Body:     encryptedResp,
	})

	if err != nil {
		log.Errorf("failed sending SyncResponse %v", err)
		return status.Errorf(codes.Internal, "error handling request")
	}

	return nil
}

// GetDeviceAuthorizationFlow returns a device authorization flow information
// This is used for initiating an Oauth 2 device authorization grant flow
// which will be used by our clients to Login
func (s *GRPCServer) GetDeviceAuthorizationFlow(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		errMSG := fmt.Sprintf("error while parsing peer's Wireguard public key %s on GetDeviceAuthorizationFlow request.", req.WgPubKey)
		log.Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	err = encryption.DecryptMessage(peerKey, s.wgKey, req.Body, &proto.DeviceAuthorizationFlowRequest{})
	if err != nil {
		errMSG := fmt.Sprintf("error while decrypting peer's message with Wireguard public key %s.", req.WgPubKey)
		log.Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	if s.config.DeviceAuthorizationFlow == nil || s.config.DeviceAuthorizationFlow.Provider == string(NONE) {
		return nil, status.Error(codes.NotFound, "no device authorization flow information available")
	}

	provider, ok := proto.DeviceAuthorizationFlowProvider_value[strings.ToUpper(s.config.DeviceAuthorizationFlow.Provider)]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "no provider found in the protocol for %s", s.config.DeviceAuthorizationFlow.Provider)
	}

	flowInfoResp := &proto.DeviceAuthorizationFlow{
		Provider: proto.DeviceAuthorizationFlowProvider(provider),
		ProviderConfig: &proto.ProviderConfig{
			ClientID:           s.config.DeviceAuthorizationFlow.ProviderConfig.ClientID,
			ClientSecret:       s.config.DeviceAuthorizationFlow.ProviderConfig.ClientSecret,
			Domain:             s.config.DeviceAuthorizationFlow.ProviderConfig.Domain,
			Audience:           s.config.DeviceAuthorizationFlow.ProviderConfig.Audience,
			DeviceAuthEndpoint: s.config.DeviceAuthorizationFlow.ProviderConfig.DeviceAuthEndpoint,
			TokenEndpoint:      s.config.DeviceAuthorizationFlow.ProviderConfig.TokenEndpoint,
		},
	}

	encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, flowInfoResp)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encrypt no device authorization flow information")
	}

	return &proto.EncryptedMessage{
		WgPubKey: s.wgKey.PublicKey().String(),
		Body:     encryptedResp,
	}, nil
}
