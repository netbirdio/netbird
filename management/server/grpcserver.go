package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	pb "github.com/golang/protobuf/proto" // nolint
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	internalStatus "github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

// GRPCServer an instance of a Management gRPC API server
type GRPCServer struct {
	accountManager AccountManager
	wgKey          wgtypes.Key
	proto.UnimplementedManagementServiceServer
	peersUpdateManager     *PeersUpdateManager
	config                 *Config
	turnCredentialsManager TURNCredentialsManager
	jwtValidator           *jwtclaims.JWTValidator
	jwtClaimsExtractor     *jwtclaims.ClaimsExtractor
	appMetrics             telemetry.AppMetrics
	ephemeralManager       *EphemeralManager
}

// NewServer creates a new Management server
func NewServer(config *Config, accountManager AccountManager, peersUpdateManager *PeersUpdateManager, turnCredentialsManager TURNCredentialsManager, appMetrics telemetry.AppMetrics, ephemeralManager *EphemeralManager) (*GRPCServer, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	var jwtValidator *jwtclaims.JWTValidator

	if config.HttpConfig != nil && config.HttpConfig.AuthIssuer != "" && config.HttpConfig.AuthAudience != "" && validateURL(config.HttpConfig.AuthKeysLocation) {
		jwtValidator, err = jwtclaims.NewJWTValidator(
			config.HttpConfig.AuthIssuer,
			config.GetAuthAudiences(),
			config.HttpConfig.AuthKeysLocation,
			config.HttpConfig.IdpSignKeyRefreshEnabled,
		)
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
		jwtValidator:           jwtValidator,
		jwtClaimsExtractor:     jwtClaimsExtractor,
		appMetrics:             appMetrics,
		ephemeralManager:       ephemeralManager,
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

func getRealIP(ctx context.Context) net.IP {
	if addr, ok := realip.FromContext(ctx); ok {
		return net.IP(addr.AsSlice())
	}
	return nil
}

// Sync validates the existence of a connecting peer, sends an initial state (all available for the connecting peers) and
// notifies the connected peer of any updates (e.g. new peers under the same account)
func (s *GRPCServer) Sync(req *proto.EncryptedMessage, srv proto.ManagementService_SyncServer) error {
	reqStart := time.Now()
	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountSyncRequest()
	}
	realIP := getRealIP(srv.Context())
	log.Debugf("Sync request from peer [%s] [%s]", req.WgPubKey, realIP.String())

	syncReq := &proto.SyncRequest{}
	peerKey, err := s.parseRequest(req, syncReq)
	if err != nil {
		return err
	}

	peer, netMap, err := s.accountManager.SyncAndMarkPeer(peerKey.String(), realIP)
	if err != nil {
		return mapError(err)
	}

	err = s.sendInitialSync(peerKey, peer, netMap, srv)
	if err != nil {
		log.Debugf("error while sending initial sync for %s: %v", peerKey.String(), err)
		return err
	}

	updates := s.peersUpdateManager.CreateChannel(peer.ID)

	s.ephemeralManager.OnPeerConnected(peer)

	if s.config.TURNConfig.TimeBasedCredentials {
		s.turnCredentialsManager.SetupRefresh(peer.ID)
	}

	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountSyncRequestDuration(time.Since(reqStart))
	}

	// keep a connection to the peer and send updates when available
	for {
		select {
		// condition when there are some updates
		case update, open := <-updates:

			if s.appMetrics != nil {
				s.appMetrics.GRPCMetrics().UpdateChannelQueueLength(len(updates) + 1)
			}

			if !open {
				log.Debugf("updates channel for peer %s was closed", peerKey.String())
				s.cancelPeerRoutines(peer)
				return nil
			}
			log.Debugf("received an update for peer %s", peerKey.String())

			encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, update.Update)
			if err != nil {
				s.cancelPeerRoutines(peer)
				return status.Errorf(codes.Internal, "failed processing update message")
			}

			err = srv.SendMsg(&proto.EncryptedMessage{
				WgPubKey: s.wgKey.PublicKey().String(),
				Body:     encryptedResp,
			})
			if err != nil {
				s.cancelPeerRoutines(peer)
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

func (s *GRPCServer) cancelPeerRoutines(peer *nbpeer.Peer) {
	s.peersUpdateManager.CloseChannel(peer.ID)
	s.turnCredentialsManager.CancelRefresh(peer.ID)
	_ = s.accountManager.CancelPeerRoutines(peer)
	s.ephemeralManager.OnPeerDisconnected(peer)
}

func (s *GRPCServer) validateToken(jwtToken string) (string, error) {
	if s.jwtValidator == nil {
		return "", status.Error(codes.Internal, "no jwt validator set")
	}

	token, err := s.jwtValidator.ValidateAndParse(jwtToken)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "invalid jwt token, err: %v", err)
	}
	claims := s.jwtClaimsExtractor.FromToken(token)
	// we need to call this method because if user is new, we will automatically add it to existing or create a new account
	_, _, err = s.accountManager.GetAccountFromToken(claims)
	if err != nil {
		return "", status.Errorf(codes.Internal, "unable to fetch account with claims, err: %v", err)
	}

	if err := s.accountManager.CheckUserAccessByJWTGroups(claims); err != nil {
		return "", status.Errorf(codes.PermissionDenied, err.Error())
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
	log.Errorf("got an unhandled error: %s", err)
	return status.Errorf(codes.Internal, "failed handling request")
}

func extractPeerMeta(loginReq *proto.LoginRequest) nbpeer.PeerSystemMeta {
	osVersion := loginReq.GetMeta().GetOSVersion()
	if osVersion == "" {
		osVersion = loginReq.GetMeta().GetCore()
	}

	networkAddresses := make([]nbpeer.NetworkAddress, 0, len(loginReq.GetMeta().GetNetworkAddresses()))
	for _, addr := range loginReq.GetMeta().GetNetworkAddresses() {
		netAddr, err := netip.ParsePrefix(addr.GetNetIP())
		if err != nil {
			log.Warnf("failed to parse netip address, %s: %v", addr.GetNetIP(), err)
			continue
		}
		networkAddresses = append(networkAddresses, nbpeer.NetworkAddress{
			NetIP: netAddr,
			Mac:   addr.GetMac(),
		})
	}

	return nbpeer.PeerSystemMeta{
		Hostname:           loginReq.GetMeta().GetHostname(),
		GoOS:               loginReq.GetMeta().GetGoOS(),
		Kernel:             loginReq.GetMeta().GetKernel(),
		Platform:           loginReq.GetMeta().GetPlatform(),
		OS:                 loginReq.GetMeta().GetOS(),
		OSVersion:          osVersion,
		WtVersion:          loginReq.GetMeta().GetWiretrusteeVersion(),
		UIVersion:          loginReq.GetMeta().GetUiVersion(),
		KernelVersion:      loginReq.GetMeta().GetKernelVersion(),
		NetworkAddresses:   networkAddresses,
		SystemSerialNumber: loginReq.GetMeta().GetSysSerialNumber(),
		SystemProductName:  loginReq.GetMeta().GetSysProductName(),
		SystemManufacturer: loginReq.GetMeta().GetSysManufacturer(),
		Environment: nbpeer.Environment{
			Cloud:    loginReq.GetMeta().GetEnvironment().GetCloud(),
			Platform: loginReq.GetMeta().GetEnvironment().GetPlatform(),
		},
		Ipv6Supported:      loginReq.GetMeta().GetIpv6Supported(),
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
	reqStart := time.Now()
	defer func() {
		if s.appMetrics != nil {
			s.appMetrics.GRPCMetrics().CountLoginRequestDuration(time.Since(reqStart))
		}
	}()
	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountLoginRequest()
	}
	realIP := getRealIP(ctx)
	log.Debugf("Login request from peer [%s] [%s]", req.WgPubKey, realIP.String())

	loginReq := &proto.LoginRequest{}
	peerKey, err := s.parseRequest(req, loginReq)
	if err != nil {
		return nil, err
	}

	if loginReq.GetMeta() == nil {
		msg := status.Errorf(codes.FailedPrecondition,
			"peer system meta has to be provided to log in. Peer %s, remote addr %s", peerKey.String(), realIP)
		log.Warn(msg)
		return nil, msg
	}

	userID := ""
	// JWT token is not always provided, it is fine for userID to be empty cuz it might be that peer is already registered,
	// or it uses a setup key to register.

	if loginReq.GetJwtToken() != "" {
		for i := 0; i < 3; i++ {
			userID, err = s.validateToken(loginReq.GetJwtToken())
			if err == nil {
				break
			}
			log.Warnf("failed validating JWT token sent from peer %s with error %v. "+
				"Trying again as it may be due to the IdP cache issue", peerKey, err)
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			return nil, err
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
		ConnectionIP:    realIP,
	})

	if err != nil {
		log.Warnf("failed logging in peer %s: %s", peerKey, err)
		return nil, mapError(err)
	}

	// if the login request contains setup key then it is a registration request
	if loginReq.GetSetupKey() != "" {
		s.ephemeralManager.OnPeerDisconnected(peer)
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

func toPeerConfig(peer *nbpeer.Peer, network *Network, dnsName string) *proto.PeerConfig {
	netmask, _ := network.Net.Mask.Size()
	address6 := ""
	if network.Net6 != nil && peer.IP6 != nil {
		netmask6, _ := network.Net6.Mask.Size()
		address6 = fmt.Sprintf("%s/%d", peer.IP6.String(), netmask6)
	}
	fqdn := peer.FQDN(dnsName)
	return &proto.PeerConfig{
		Address:   fmt.Sprintf("%s/%d", peer.IP.String(), netmask), // take it from the network
		Address6:  address6,
		SshConfig: &proto.SSHConfig{SshEnabled: peer.SSHEnabled},
		Fqdn:      fqdn,
	}
}

func toRemotePeerConfig(peers []*nbpeer.Peer, dnsName string, v6Enabled bool) []*proto.RemotePeerConfig {
	remotePeers := []*proto.RemotePeerConfig{}
	for _, rPeer := range peers {
		fqdn := rPeer.FQDN(dnsName)
		allowedIps := []string{fmt.Sprintf(AllowedIPsFormat, rPeer.IP)}
		if rPeer.IP6 != nil && v6Enabled {
			allowedIps = append(allowedIps, fmt.Sprintf(AllowedIP6sFormat, *rPeer.IP6))
		}
		remotePeers = append(remotePeers, &proto.RemotePeerConfig{
			WgPubKey:   rPeer.Key,
			AllowedIps: allowedIps,
			SshConfig:  &proto.SSHConfig{SshPubKey: []byte(rPeer.SSHKey)},
			Fqdn:       fqdn,
		})
	}
	return remotePeers
}

func toSyncResponse(config *Config, peer *nbpeer.Peer, turnCredentials *TURNCredentials, networkMap *NetworkMap, dnsName string) *proto.SyncResponse {
	wtConfig := toWiretrusteeConfig(config, turnCredentials)

	pConfig := toPeerConfig(peer, networkMap.Network, dnsName)

	remotePeers := toRemotePeerConfig(networkMap.Peers, dnsName, peer.IP6 != nil)

	routesUpdate := toProtocolRoutes(networkMap.Routes)

	dnsUpdate := toProtocolDNSConfig(networkMap.DNSConfig)

	offlinePeers := toRemotePeerConfig(networkMap.OfflinePeers, dnsName, peer.IP6 != nil)

	firewallRules := toProtocolFirewallRules(networkMap.FirewallRules)

	return &proto.SyncResponse{
		WiretrusteeConfig:  wtConfig,
		PeerConfig:         pConfig,
		RemotePeers:        remotePeers,
		RemotePeersIsEmpty: len(remotePeers) == 0,
		NetworkMap: &proto.NetworkMap{
			Serial:               networkMap.Network.CurrentSerial(),
			PeerConfig:           pConfig,
			RemotePeers:          remotePeers,
			OfflinePeers:         offlinePeers,
			RemotePeersIsEmpty:   len(remotePeers) == 0,
			Routes:               routesUpdate,
			DNSConfig:            dnsUpdate,
			FirewallRules:        firewallRules,
			FirewallRulesIsEmpty: len(firewallRules) == 0,
		},
	}
}

// IsHealthy indicates whether the service is healthy
func (s *GRPCServer) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

// sendInitialSync sends initial proto.SyncResponse to the peer requesting synchronization
func (s *GRPCServer) sendInitialSync(peerKey wgtypes.Key, peer *nbpeer.Peer, networkMap *NetworkMap, srv proto.ManagementService_SyncServer) error {
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
			Scope:              s.config.DeviceAuthorizationFlow.ProviderConfig.Scope,
			UseIDToken:         s.config.DeviceAuthorizationFlow.ProviderConfig.UseIDToken,
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

// GetPKCEAuthorizationFlow returns a pkce authorization flow information
// This is used for initiating an Oauth 2 pkce authorization grant flow
// which will be used by our clients to Login
func (s *GRPCServer) GetPKCEAuthorizationFlow(_ context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		errMSG := fmt.Sprintf("error while parsing peer's Wireguard public key %s on GetPKCEAuthorizationFlow request.", req.WgPubKey)
		log.Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	err = encryption.DecryptMessage(peerKey, s.wgKey, req.Body, &proto.PKCEAuthorizationFlowRequest{})
	if err != nil {
		errMSG := fmt.Sprintf("error while decrypting peer's message with Wireguard public key %s.", req.WgPubKey)
		log.Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	if s.config.PKCEAuthorizationFlow == nil {
		return nil, status.Error(codes.NotFound, "no pkce authorization flow information available")
	}

	flowInfoResp := &proto.PKCEAuthorizationFlow{
		ProviderConfig: &proto.ProviderConfig{
			Audience:              s.config.PKCEAuthorizationFlow.ProviderConfig.Audience,
			ClientID:              s.config.PKCEAuthorizationFlow.ProviderConfig.ClientID,
			ClientSecret:          s.config.PKCEAuthorizationFlow.ProviderConfig.ClientSecret,
			TokenEndpoint:         s.config.PKCEAuthorizationFlow.ProviderConfig.TokenEndpoint,
			AuthorizationEndpoint: s.config.PKCEAuthorizationFlow.ProviderConfig.AuthorizationEndpoint,
			Scope:                 s.config.PKCEAuthorizationFlow.ProviderConfig.Scope,
			RedirectURLs:          s.config.PKCEAuthorizationFlow.ProviderConfig.RedirectURLs,
			UseIDToken:            s.config.PKCEAuthorizationFlow.ProviderConfig.UseIDToken,
		},
	}

	encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, flowInfoResp)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encrypt no pkce authorization flow information")
	}

	return &proto.EncryptedMessage{
		WgPubKey: s.wgKey.PublicKey().String(),
		Body:     encryptedResp,
	}, nil
}
