package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	pb "github.com/golang/protobuf/proto" // nolint
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	integrationsConfig "github.com/netbirdio/management-integrations/integrations/config"

	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/store"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/auth"
	nbContext "github.com/netbirdio/netbird/management/server/context"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	internalStatus "github.com/netbirdio/netbird/shared/management/status"
)

// GRPCServer an instance of a Management gRPC API server
type GRPCServer struct {
	accountManager  account.Manager
	settingsManager settings.Manager
	wgKey           wgtypes.Key
	proto.UnimplementedManagementServiceServer
	peersUpdateManager      *PeersUpdateManager
	peersJobManager         *PeersJobManager
	config                  *types.Config
	secretsManager          SecretsManager
	appMetrics              telemetry.AppMetrics
	ephemeralManager        *EphemeralManager
	peerLocks               sync.Map
	authManager             auth.Manager
	integratedPeerValidator integrated_validator.IntegratedValidator
}

// NewServer creates a new Management server
func NewServer(
	ctx context.Context,
	config *types.Config,
	accountManager account.Manager,
	settingsManager settings.Manager,
	peersUpdateManager *PeersUpdateManager,
	peersJobManager *PeersJobManager,
	secretsManager SecretsManager,
	appMetrics telemetry.AppMetrics,
	ephemeralManager *EphemeralManager,
	authManager auth.Manager,
	integratedPeerValidator integrated_validator.IntegratedValidator,
) (*GRPCServer, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	if appMetrics != nil {
		// update gauge based on number of connected peers which is equal to open gRPC streams
		err = appMetrics.GRPCMetrics().RegisterConnectedStreams(func() int64 {
			return int64(len(peersUpdateManager.peerChannels))
		})
		err = appMetrics.GRPCMetrics().RegisterConnectedStreams(func() int64 {
			return int64(len(peersJobManager.jobRequestChannels))
		})
		err = appMetrics.GRPCMetrics().RegisterConnectedStreams(func() int64 {
			return int64(len(peersJobManager.jobResponseChannels))
		})

		if err != nil {
			return nil, err
		}
	}

	return &GRPCServer{
		wgKey: key,
		// peerKey -> event channel
		peersUpdateManager:      peersUpdateManager,
		peersJobManager:         peersJobManager,
		accountManager:          accountManager,
		settingsManager:         settingsManager,
		config:                  config,
		secretsManager:          secretsManager,
		authManager:             authManager,
		appMetrics:              appMetrics,
		ephemeralManager:        ephemeralManager,
		integratedPeerValidator: integratedPeerValidator,
	}, nil
}

func (s *GRPCServer) GetServerKey(ctx context.Context, req *proto.Empty) (*proto.ServerKeyResponse, error) {
	ip := ""
	p, ok := peer.FromContext(ctx)
	if ok {
		ip = p.Addr.String()
	}

	log.WithContext(ctx).Tracef("GetServerKey request from %s", ip)
	start := time.Now()
	defer func() {
		log.WithContext(ctx).Tracef("GetServerKey from %s took %v", ip, time.Since(start))
	}()

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

func (s *GRPCServer) Job(req *proto.EncryptedMessage, srv proto.ManagementService_JobServer) error {
	reqStart := time.Now()
	ctx := srv.Context()

	jobReq := &proto.JobRequest{}
	peerKey, err := s.parseRequest(ctx, req, jobReq)
	if err != nil {
		return err
	}

	// nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.PeerIDKey, peerKey.String())
	unlock := s.acquirePeerLockByUID(ctx, peerKey.String())
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()

	accountID, err := s.accountManager.GetAccountIDForPeerKey(ctx, peerKey.String())
	if err != nil {
		// nolint:staticcheck
		ctx = context.WithValue(ctx, nbContext.AccountIDKey, "UNKNOWN")
		log.WithContext(ctx).Tracef("peer %s is not registered", peerKey.String())
		if errStatus, ok := internalStatus.FromError(err); ok && errStatus.Type() == internalStatus.NotFound {
			return status.Errorf(codes.PermissionDenied, "peer is not registered")
		}
		return err
	}

	// nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.AccountIDKey, accountID)

	realIP := getRealIP(ctx)
	peer, _, _, err := s.accountManager.SyncAndMarkPeer(ctx, accountID, peerKey.String(), nbpeer.PeerSystemMeta{}, realIP)
	if err != nil {
		log.WithContext(ctx).Debugf("error while syncing peer %s: %v", peerKey.String(), err)
		return mapError(ctx, err)
	}

	if err := s.sendInitialJob(ctx, peerKey, srv); err != nil {
		log.WithContext(ctx).Debugf("error while sending initial job for %s: %v", peerKey.String(), err)
		return err
	}

	updates := s.peersJobManager.CreateRequestChannel(ctx, peer.ID)

	s.ephemeralManager.OnPeerConnected(ctx, peer)

	s.secretsManager.SetupRefresh(ctx, accountID, peer.ID)

	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountSyncRequestDuration(time.Since(reqStart))
	}

	unlock()
	unlock = nil

	return s.handleJobs(ctx, accountID, peerKey, peer, updates, srv)
}

// Sync validates the existence of a connecting peer, sends an initial state (all available for the connecting peers) and
// notifies the connected peer of any updates (e.g. new peers under the same account)
func (s *GRPCServer) Sync(req *proto.EncryptedMessage, srv proto.ManagementService_SyncServer) error {
	reqStart := time.Now()
	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountSyncRequest()
	}

	ctx := srv.Context()

	syncReq := &proto.SyncRequest{}
	peerKey, err := s.parseRequest(ctx, req, syncReq)
	if err != nil {
		return err
	}

	// nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.PeerIDKey, peerKey.String())

	unlock := s.acquirePeerLockByUID(ctx, peerKey.String())
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()

	accountID, err := s.accountManager.GetAccountIDForPeerKey(ctx, peerKey.String())
	if err != nil {
		// nolint:staticcheck
		ctx = context.WithValue(ctx, nbContext.AccountIDKey, "UNKNOWN")
		log.WithContext(ctx).Tracef("peer %s is not registered", peerKey.String())
		if errStatus, ok := internalStatus.FromError(err); ok && errStatus.Type() == internalStatus.NotFound {
			return status.Errorf(codes.PermissionDenied, "peer is not registered")
		}
		return err
	}

	// nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.AccountIDKey, accountID)

	realIP := getRealIP(ctx)
	log.WithContext(ctx).Debugf("Sync request from peer [%s] [%s]", req.WgPubKey, realIP.String())

	if syncReq.GetMeta() == nil {
		log.WithContext(ctx).Tracef("peer system meta has to be provided on sync. Peer %s, remote addr %s", peerKey.String(), realIP)
	}

	peer, netMap, postureChecks, err := s.accountManager.SyncAndMarkPeer(ctx, accountID, peerKey.String(), extractPeerMeta(ctx, syncReq.GetMeta()), realIP)
	if err != nil {
		log.WithContext(ctx).Debugf("error while syncing peer %s: %v", peerKey.String(), err)
		return mapError(ctx, err)
	}

	err = s.sendInitialUpdate(ctx, peerKey, peer, netMap, postureChecks, srv)
	if err != nil {
		log.WithContext(ctx).Debugf("error while sending initial sync for %s: %v", peerKey.String(), err)
		return err
	}

	updates := s.peersUpdateManager.CreateChannel(ctx, peer.ID)

	s.ephemeralManager.OnPeerConnected(ctx, peer)

	s.secretsManager.SetupRefresh(ctx, accountID, peer.ID)

	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountSyncRequestDuration(time.Since(reqStart))
	}

	unlock()
	unlock = nil

	log.WithContext(ctx).Debugf("Sync: took %v", time.Since(reqStart))

	return s.handleUpdates(ctx, accountID, peerKey, peer, updates, srv)
}

func (s *GRPCServer) handleJobs(ctx context.Context, accountID string, peerKey wgtypes.Key, peer *nbpeer.Peer, updates chan *proto.JobRequest, srv proto.ManagementService_JobServer) error {
	log.WithContext(ctx).Tracef("starting to handle updates for peer %s", peerKey.String())
	for {
		select {
		// condition when there are some updates
		case update, open := <-updates:
			if s.appMetrics != nil {
				s.appMetrics.GRPCMetrics().UpdateChannelQueueLength(len(updates) + 1)
			}

			if !open {
				log.WithContext(ctx).Debugf("Jobs channel for peer %s was closed", peerKey.String())
				s.closeJobChannels(ctx, accountID, peer)
				return nil
			}
			log.WithContext(ctx).Debugf("received an Job for peer %s", peerKey.String())
			encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, update)
			if err != nil {
				s.closeJobChannels(ctx, accountID, peer)
				return status.Errorf(codes.Internal, "failed processing job message")
			}

			if err := s.sendRequest(ctx, accountID, peerKey, peer, encryptedResp, srv); err != nil {
				s.closeJobChannels(ctx, accountID, peer)
				return err
			}

		// condition when client <-> server connection has been terminated
		case <-srv.Context().Done():
			// happens when connection drops, e.g. client disconnects
			log.WithContext(ctx).Debugf("stream of peer %s has been closed", peerKey.String())
			s.closeJobChannels(ctx, accountID, peer)
			return srv.Context().Err()
		}
	}
}

// handleUpdates sends updates to the connected peer until the updates channel is closed.
func (s *GRPCServer) handleUpdates(ctx context.Context, accountID string, peerKey wgtypes.Key, peer *nbpeer.Peer, updates chan *UpdateMessage, srv proto.ManagementService_SyncServer) error {
	log.WithContext(ctx).Tracef("starting to handle updates for peer %s", peerKey.String())
	for {
		select {
		// condition when there are some updates
		case update, open := <-updates:
			if s.appMetrics != nil {
				s.appMetrics.GRPCMetrics().UpdateChannelQueueLength(len(updates) + 1)
			}

			if !open {
				log.WithContext(ctx).Debugf("updates channel for peer %s was closed", peerKey.String())
				s.closeUpdateChannel(ctx, accountID, peer)
				return nil
			}
			log.WithContext(ctx).Debugf("received an update for peer %s", peerKey.String())
			encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, update.Update)
			if err != nil {
				s.closeUpdateChannel(ctx, accountID, peer)
				return status.Errorf(codes.Internal, "failed processing update message")
			}
			if err := s.sendRequest(ctx, accountID, peerKey, peer, encryptedResp, srv); err != nil {
				s.closeUpdateChannel(ctx, accountID, peer)
				return err
			}

		// condition when client <-> server connection has been terminated
		case <-srv.Context().Done():
			// happens when connection drops, e.g. client disconnects
			log.WithContext(ctx).Debugf("stream of peer %s has been closed", peerKey.String())
			s.closeUpdateChannel(ctx,accountID, peer)
			return srv.Context().Err()
		}
	}
}

// sendJob encrypts the update message using the peer key and the server's wireguard key,
// then sends the encrypted message to the connected peer via the sync server.
func (s *GRPCServer) sendRequest(ctx context.Context, accountID string, peerKey wgtypes.Key, peer *nbpeer.Peer, encryptedResp []byte, srv proto.ManagementService_SyncServer) error {
	log.WithContext(ctx).Debugf("sending xxxx %d", len(encryptedResp))
	err := srv.SendMsg(&proto.EncryptedMessage{
		WgPubKey: s.wgKey.PublicKey().String(),
		Body:     encryptedResp,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed sending update message")
	}
	log.WithContext(ctx).Debugf("sent an update to peer %s", peerKey.String())
	return nil
}

func (s *GRPCServer) disconnectPeer(ctx context.Context, accountID string, peer *nbpeer.Peer) {
	unlock := s.acquirePeerLockByUID(ctx, peer.Key)
	defer unlock()

	// Account-level cleanup
	if err := s.accountManager.OnPeerDisconnected(ctx, accountID, peer.Key); err != nil {
		log.WithContext(ctx).Errorf("failed to disconnect peer %s properly: %v", peer.Key, err)
	}

	// Secrets / ephemeral managers
	s.secretsManager.CancelRefresh(peer.ID)
	s.ephemeralManager.OnPeerDisconnected(ctx, peer)

	log.WithContext(ctx).Tracef("peer %s has been fully disconnected", peer.Key)
}

// Only closes job channels (used when job stream ends / errors)
func (s *GRPCServer) closeJobChannels(ctx context.Context, accountID string, peer *nbpeer.Peer) {
	s.peersJobManager.CloseRequestChannel(ctx, peer.ID)
	s.peersJobManager.CloseResponseChannel(ctx, peer.ID)
	s.disconnectPeer(ctx, accountID, peer)
}

// Only closes update channels (used when sync stream ends / errors)
func (s *GRPCServer) closeUpdateChannel(ctx context.Context, accountID string, peer *nbpeer.Peer) {
	s.peersUpdateManager.CloseChannel(ctx, peer.ID)
	s.disconnectPeer(ctx, accountID, peer)
}

func (s *GRPCServer) validateToken(ctx context.Context, jwtToken string) (string, error) {
	if s.authManager == nil {
		return "", status.Errorf(codes.Internal, "missing auth manager")
	}

	userAuth, token, err := s.authManager.ValidateAndParseToken(ctx, jwtToken)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "invalid jwt token, err: %v", err)
	}

	// we need to call this method because if user is new, we will automatically add it to existing or create a new account
	accountId, _, err := s.accountManager.GetAccountIDFromUserAuth(ctx, userAuth)
	if err != nil {
		return "", status.Errorf(codes.Internal, "unable to fetch account with claims, err: %v", err)
	}

	if userAuth.AccountId != accountId {
		log.WithContext(ctx).Debugf("gRPC server sets accountId from ensure, before %s, now %s", userAuth.AccountId, accountId)
		userAuth.AccountId = accountId
	}

	userAuth, err = s.authManager.EnsureUserAccessByJWTGroups(ctx, userAuth, token)
	if err != nil {
		return "", status.Error(codes.PermissionDenied, err.Error())
	}

	err = s.accountManager.SyncUserJWTGroups(ctx, userAuth)
	if err != nil {
		log.WithContext(ctx).Errorf("gRPC server failed to sync user JWT groups: %s", err)
	}

	return userAuth.UserId, nil
}

func (s *GRPCServer) acquirePeerLockByUID(ctx context.Context, uniqueID string) (unlock func()) {
	log.WithContext(ctx).Tracef("acquiring peer lock for ID %s", uniqueID)

	start := time.Now()
	value, _ := s.peerLocks.LoadOrStore(uniqueID, &sync.RWMutex{})
	mtx := value.(*sync.RWMutex)
	mtx.Lock()
	log.WithContext(ctx).Tracef("acquired peer lock for ID %s in %v", uniqueID, time.Since(start))
	start = time.Now()

	unlock = func() {
		mtx.Unlock()
		log.WithContext(ctx).Tracef("released peer lock for ID %s in %v", uniqueID, time.Since(start))
	}

	return unlock
}

// maps internal internalStatus.Error to gRPC status.Error
func mapError(ctx context.Context, err error) error {
	if e, ok := internalStatus.FromError(err); ok {
		switch e.Type() {
		case internalStatus.PermissionDenied:
			return status.Error(codes.PermissionDenied, e.Message)
		case internalStatus.Unauthorized:
			return status.Error(codes.PermissionDenied, e.Message)
		case internalStatus.Unauthenticated:
			return status.Error(codes.PermissionDenied, e.Message)
		case internalStatus.PreconditionFailed:
			return status.Error(codes.FailedPrecondition, e.Message)
		case internalStatus.NotFound:
			return status.Error(codes.NotFound, e.Message)
		default:
		}
	}
	log.WithContext(ctx).Errorf("got an unhandled error: %s", err)
	return status.Errorf(codes.Internal, "failed handling request")
}

func extractPeerMeta(ctx context.Context, meta *proto.PeerSystemMeta) nbpeer.PeerSystemMeta {
	if meta == nil {
		return nbpeer.PeerSystemMeta{}
	}

	osVersion := meta.GetOSVersion()
	if osVersion == "" {
		osVersion = meta.GetCore()
	}

	networkAddresses := make([]nbpeer.NetworkAddress, 0, len(meta.GetNetworkAddresses()))
	for _, addr := range meta.GetNetworkAddresses() {
		netAddr, err := netip.ParsePrefix(addr.GetNetIP())
		if err != nil {
			log.WithContext(ctx).Warnf("failed to parse netip address, %s: %v", addr.GetNetIP(), err)
			continue
		}
		networkAddresses = append(networkAddresses, nbpeer.NetworkAddress{
			NetIP: netAddr,
			Mac:   addr.GetMac(),
		})
	}

	files := make([]nbpeer.File, 0, len(meta.GetFiles()))
	for _, file := range meta.GetFiles() {
		files = append(files, nbpeer.File{
			Path:             file.GetPath(),
			Exist:            file.GetExist(),
			ProcessIsRunning: file.GetProcessIsRunning(),
		})
	}

	return nbpeer.PeerSystemMeta{
		Hostname:           meta.GetHostname(),
		GoOS:               meta.GetGoOS(),
		Kernel:             meta.GetKernel(),
		Platform:           meta.GetPlatform(),
		OS:                 meta.GetOS(),
		OSVersion:          osVersion,
		WtVersion:          meta.GetNetbirdVersion(),
		UIVersion:          meta.GetUiVersion(),
		KernelVersion:      meta.GetKernelVersion(),
		NetworkAddresses:   networkAddresses,
		SystemSerialNumber: meta.GetSysSerialNumber(),
		SystemProductName:  meta.GetSysProductName(),
		SystemManufacturer: meta.GetSysManufacturer(),
		Environment: nbpeer.Environment{
			Cloud:    meta.GetEnvironment().GetCloud(),
			Platform: meta.GetEnvironment().GetPlatform(),
		},
		Flags: nbpeer.Flags{
			RosenpassEnabled:      meta.GetFlags().GetRosenpassEnabled(),
			RosenpassPermissive:   meta.GetFlags().GetRosenpassPermissive(),
			ServerSSHAllowed:      meta.GetFlags().GetServerSSHAllowed(),
			DisableClientRoutes:   meta.GetFlags().GetDisableClientRoutes(),
			DisableServerRoutes:   meta.GetFlags().GetDisableServerRoutes(),
			DisableDNS:            meta.GetFlags().GetDisableDNS(),
			DisableFirewall:       meta.GetFlags().GetDisableFirewall(),
			BlockLANAccess:        meta.GetFlags().GetBlockLANAccess(),
			BlockInbound:          meta.GetFlags().GetBlockInbound(),
			LazyConnectionEnabled: meta.GetFlags().GetLazyConnectionEnabled(),
		},
		Files: files,
	}
}

func (s *GRPCServer) parseRequest(ctx context.Context, req *proto.EncryptedMessage, parsed pb.Message) (wgtypes.Key, error) {
	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		log.WithContext(ctx).Warnf("error while parsing peer's WireGuard public key %s.", req.WgPubKey)
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
	log.WithContext(ctx).Debugf("Login request from peer [%s] [%s]", req.WgPubKey, realIP.String())

	loginReq := &proto.LoginRequest{}
	peerKey, err := s.parseRequest(ctx, req, loginReq)
	if err != nil {
		return nil, err
	}

	//nolint
	ctx = context.WithValue(ctx, nbContext.PeerIDKey, peerKey.String())
	accountID, err := s.accountManager.GetAccountIDForPeerKey(ctx, peerKey.String())
	if err != nil {
		// this case should not happen and already indicates an issue but we don't want the system to fail due to being unable to log in detail
		accountID = "UNKNOWN"
	}
	//nolint
	ctx = context.WithValue(ctx, nbContext.AccountIDKey, accountID)

	if loginReq.GetMeta() == nil {
		msg := status.Errorf(codes.FailedPrecondition,
			"peer system meta has to be provided to log in. Peer %s, remote addr %s", peerKey.String(), realIP)
		log.WithContext(ctx).Warn(msg)
		return nil, msg
	}

	userID, err := s.processJwtToken(ctx, loginReq, peerKey)
	if err != nil {
		return nil, err
	}

	var sshKey []byte
	if loginReq.GetPeerKeys() != nil {
		sshKey = loginReq.GetPeerKeys().GetSshPubKey()
	}

	peer, netMap, postureChecks, err := s.accountManager.LoginPeer(ctx, types.PeerLogin{
		WireGuardPubKey: peerKey.String(),
		SSHKey:          string(sshKey),
		Meta:            extractPeerMeta(ctx, loginReq.GetMeta()),
		UserID:          userID,
		SetupKey:        loginReq.GetSetupKey(),
		ConnectionIP:    realIP,
		ExtraDNSLabels:  loginReq.GetDnsLabels(),
	})
	if err != nil {
		log.WithContext(ctx).Warnf("failed logging in peer %s: %s", peerKey, err)
		return nil, mapError(ctx, err)
	}

	// if the login request contains setup key then it is a registration request
	if loginReq.GetSetupKey() != "" {
		s.ephemeralManager.OnPeerDisconnected(ctx, peer)
	}

	loginResp, err := s.prepareLoginResponse(ctx, peer, netMap, postureChecks)
	if err != nil {
		log.WithContext(ctx).Warnf("failed preparing login response for peer %s: %s", peerKey, err)
		return nil, status.Errorf(codes.Internal, "failed logging in peer")
	}

	encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, loginResp)
	if err != nil {
		log.WithContext(ctx).Warnf("failed encrypting peer %s message", peer.ID)
		return nil, status.Errorf(codes.Internal, "failed logging in peer")
	}

	return &proto.EncryptedMessage{
		WgPubKey: s.wgKey.PublicKey().String(),
		Body:     encryptedResp,
	}, nil
}

func (s *GRPCServer) prepareLoginResponse(ctx context.Context, peer *nbpeer.Peer, netMap *types.NetworkMap, postureChecks []*posture.Checks) (*proto.LoginResponse, error) {
	var relayToken *Token
	var err error
	if s.config.Relay != nil && len(s.config.Relay.Addresses) > 0 {
		relayToken, err = s.secretsManager.GenerateRelayToken()
		if err != nil {
			log.Errorf("failed generating Relay token: %v", err)
		}
	}

	settings, err := s.settingsManager.GetSettings(ctx, peer.AccountID, activity.SystemInitiator)
	if err != nil {
		log.WithContext(ctx).Warnf("failed getting settings for peer %s: %s", peer.Key, err)
		return nil, status.Errorf(codes.Internal, "failed getting settings")
	}

	// if peer has reached this point then it has logged in
	loginResp := &proto.LoginResponse{
		NetbirdConfig: toNetbirdConfig(s.config, nil, relayToken, nil),
		PeerConfig:    toPeerConfig(peer, netMap.Network, s.accountManager.GetDNSDomain(settings), settings),
		Checks:        toProtocolChecks(ctx, postureChecks),
	}

	return loginResp, nil
}

// processJwtToken validates the existence of a JWT token in the login request, and returns the corresponding user ID if
// the token is valid.
//
// The user ID can be empty if the token is not provided, which is acceptable if the peer is already
// registered or if it uses a setup key to register.
func (s *GRPCServer) processJwtToken(ctx context.Context, loginReq *proto.LoginRequest, peerKey wgtypes.Key) (string, error) {
	userID := ""
	if loginReq.GetJwtToken() != "" {
		var err error
		for i := 0; i < 3; i++ {
			userID, err = s.validateToken(ctx, loginReq.GetJwtToken())
			if err == nil {
				break
			}
			log.WithContext(ctx).Warnf("failed validating JWT token sent from peer %s with error %v. "+
				"Trying again as it may be due to the IdP cache issue", peerKey.String(), err)
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			return "", err
		}
	}
	return userID, nil
}

func ToResponseProto(configProto types.Protocol) proto.HostConfig_Protocol {
	switch configProto {
	case types.UDP:
		return proto.HostConfig_UDP
	case types.DTLS:
		return proto.HostConfig_DTLS
	case types.HTTP:
		return proto.HostConfig_HTTP
	case types.HTTPS:
		return proto.HostConfig_HTTPS
	case types.TCP:
		return proto.HostConfig_TCP
	default:
		panic(fmt.Errorf("unexpected config protocol type %v", configProto))
	}
}

func toNetbirdConfig(config *types.Config, turnCredentials *Token, relayToken *Token, extraSettings *types.ExtraSettings) *proto.NetbirdConfig {
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
	if config.TURNConfig != nil {
		for _, turn := range config.TURNConfig.Turns {
			var username string
			var password string
			if turnCredentials != nil {
				username = turnCredentials.Payload
				password = turnCredentials.Signature
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
	}

	var relayCfg *proto.RelayConfig
	if config.Relay != nil && len(config.Relay.Addresses) > 0 {
		relayCfg = &proto.RelayConfig{
			Urls: config.Relay.Addresses,
		}

		if relayToken != nil {
			relayCfg.TokenPayload = relayToken.Payload
			relayCfg.TokenSignature = relayToken.Signature
		}
	}

	var signalCfg *proto.HostConfig
	if config.Signal != nil {
		signalCfg = &proto.HostConfig{
			Uri:      config.Signal.URI,
			Protocol: ToResponseProto(config.Signal.Proto),
		}
	}

	nbConfig := &proto.NetbirdConfig{
		Stuns:  stuns,
		Turns:  turns,
		Signal: signalCfg,
		Relay:  relayCfg,
	}

	return nbConfig
}

func toPeerConfig(peer *nbpeer.Peer, network *types.Network, dnsName string, settings *types.Settings) *proto.PeerConfig {
	netmask, _ := network.Net.Mask.Size()
	fqdn := peer.FQDN(dnsName)
	return &proto.PeerConfig{
		Address:                         fmt.Sprintf("%s/%d", peer.IP.String(), netmask), // take it from the network
		SshConfig:                       &proto.SSHConfig{SshEnabled: peer.SSHEnabled},
		Fqdn:                            fqdn,
		RoutingPeerDnsResolutionEnabled: settings.RoutingPeerDNSResolutionEnabled,
		LazyConnectionEnabled:           settings.LazyConnectionEnabled,
	}
}

func toSyncResponse(ctx context.Context, config *types.Config, peer *nbpeer.Peer, turnCredentials *Token, relayCredentials *Token, networkMap *types.NetworkMap, dnsName string, checks []*posture.Checks, dnsCache *DNSConfigCache, settings *types.Settings, extraSettings *types.ExtraSettings, peerGroups []string) *proto.SyncResponse {
	response := &proto.SyncResponse{
		PeerConfig: toPeerConfig(peer, networkMap.Network, dnsName, settings),
		NetworkMap: &proto.NetworkMap{
			Serial:    networkMap.Network.CurrentSerial(),
			Routes:    toProtocolRoutes(networkMap.Routes),
			DNSConfig: toProtocolDNSConfig(networkMap.DNSConfig, dnsCache),
		},
		Checks: toProtocolChecks(ctx, checks),
	}

	nbConfig := toNetbirdConfig(config, turnCredentials, relayCredentials, extraSettings)
	extendedConfig := integrationsConfig.ExtendNetBirdConfig(peer.ID, peerGroups, nbConfig, extraSettings)
	response.NetbirdConfig = extendedConfig

	response.NetworkMap.PeerConfig = response.PeerConfig

	allPeers := make([]*proto.RemotePeerConfig, 0, len(networkMap.Peers)+len(networkMap.OfflinePeers))
	allPeers = appendRemotePeerConfig(allPeers, networkMap.Peers, dnsName)
	response.RemotePeers = allPeers
	response.NetworkMap.RemotePeers = allPeers
	response.RemotePeersIsEmpty = len(allPeers) == 0
	response.NetworkMap.RemotePeersIsEmpty = response.RemotePeersIsEmpty

	response.NetworkMap.OfflinePeers = appendRemotePeerConfig(nil, networkMap.OfflinePeers, dnsName)

	firewallRules := toProtocolFirewallRules(networkMap.FirewallRules)
	response.NetworkMap.FirewallRules = firewallRules
	response.NetworkMap.FirewallRulesIsEmpty = len(firewallRules) == 0

	routesFirewallRules := toProtocolRoutesFirewallRules(networkMap.RoutesFirewallRules)
	response.NetworkMap.RoutesFirewallRules = routesFirewallRules
	response.NetworkMap.RoutesFirewallRulesIsEmpty = len(routesFirewallRules) == 0

	if networkMap.ForwardingRules != nil {
		forwardingRules := make([]*proto.ForwardingRule, 0, len(networkMap.ForwardingRules))
		for _, rule := range networkMap.ForwardingRules {
			forwardingRules = append(forwardingRules, rule.ToProto())
		}
		response.NetworkMap.ForwardingRules = forwardingRules
	}

	return response
}

func appendRemotePeerConfig(dst []*proto.RemotePeerConfig, peers []*nbpeer.Peer, dnsName string) []*proto.RemotePeerConfig {
	for _, rPeer := range peers {
		dst = append(dst, &proto.RemotePeerConfig{
			WgPubKey:     rPeer.Key,
			AllowedIps:   []string{rPeer.IP.String() + "/32"},
			SshConfig:    &proto.SSHConfig{SshPubKey: []byte(rPeer.SSHKey)},
			Fqdn:         rPeer.FQDN(dnsName),
			AgentVersion: rPeer.Meta.WtVersion,
		})
	}
	return dst
}

// IsHealthy indicates whether the service is healthy
func (s *GRPCServer) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

func (s *GRPCServer) sendInitialJob(ctx context.Context, peerKey wgtypes.Key, srv proto.ManagementService_JobServer) error {
	plainResp := &proto.JobResponse{}
	encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, plainResp)
	if err != nil {
		return status.Errorf(codes.Internal, "error handling request")
	}

	err = srv.Send(&proto.EncryptedMessage{
		WgPubKey: s.wgKey.PublicKey().String(),
		Body:     encryptedResp,
	})

	if err != nil {
		log.WithContext(ctx).Errorf("failed sending SyncResponse %v", err)
		return status.Errorf(codes.Internal, "error handling request")
	}

	return nil
}

// sendInitialSync sends initial proto.SyncResponse to the peer requesting synchronization
func (s *GRPCServer) sendInitialUpdate(ctx context.Context, peerKey wgtypes.Key, peer *nbpeer.Peer, networkMap *types.NetworkMap, postureChecks []*posture.Checks, srv proto.ManagementService_SyncServer) error {
	var err error

	var turnToken *Token
	if s.config.TURNConfig != nil && s.config.TURNConfig.TimeBasedCredentials {
		turnToken, err = s.secretsManager.GenerateTurnToken()
		if err != nil {
			log.Errorf("failed generating TURN token: %v", err)
		}
	}

	var relayToken *Token
	if s.config.Relay != nil && len(s.config.Relay.Addresses) > 0 {
		relayToken, err = s.secretsManager.GenerateRelayToken()
		if err != nil {
			log.Errorf("failed generating Relay token: %v", err)
		}
	}

	settings, err := s.settingsManager.GetSettings(ctx, peer.AccountID, activity.SystemInitiator)
	if err != nil {
		return status.Errorf(codes.Internal, "error handling request")
	}

	peerGroups, err := getPeerGroupIDs(ctx, s.accountManager.GetStore(), peer.AccountID, peer.ID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get peer groups %s", err)
	}

	plainResp := toSyncResponse(ctx, s.config, peer, turnToken, relayToken, networkMap, s.accountManager.GetDNSDomain(settings), postureChecks, nil, settings, settings.Extra, peerGroups)

	encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, plainResp)
	if err != nil {
		return status.Errorf(codes.Internal, "error handling request")
	}

	err = srv.Send(&proto.EncryptedMessage{
		WgPubKey: s.wgKey.PublicKey().String(),
		Body:     encryptedResp,
	})

	if err != nil {
		log.WithContext(ctx).Errorf("failed sending SyncResponse %v", err)
		return status.Errorf(codes.Internal, "error handling request")
	}

	return nil
}

// GetDeviceAuthorizationFlow returns a device authorization flow information
// This is used for initiating an Oauth 2 device authorization grant flow
// which will be used by our clients to Login
func (s *GRPCServer) GetDeviceAuthorizationFlow(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	log.WithContext(ctx).Tracef("GetDeviceAuthorizationFlow request for pubKey: %s", req.WgPubKey)
	start := time.Now()
	defer func() {
		log.WithContext(ctx).Tracef("GetDeviceAuthorizationFlow for pubKey: %s took %v", req.WgPubKey, time.Since(start))
	}()

	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		errMSG := fmt.Sprintf("error while parsing peer's Wireguard public key %s on GetDeviceAuthorizationFlow request.", req.WgPubKey)
		log.WithContext(ctx).Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	err = encryption.DecryptMessage(peerKey, s.wgKey, req.Body, &proto.DeviceAuthorizationFlowRequest{})
	if err != nil {
		errMSG := fmt.Sprintf("error while decrypting peer's message with Wireguard public key %s.", req.WgPubKey)
		log.WithContext(ctx).Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	if s.config.DeviceAuthorizationFlow == nil || s.config.DeviceAuthorizationFlow.Provider == string(types.NONE) {
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
func (s *GRPCServer) GetPKCEAuthorizationFlow(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	log.WithContext(ctx).Tracef("GetPKCEAuthorizationFlow request for pubKey: %s", req.WgPubKey)
	start := time.Now()
	defer func() {
		log.WithContext(ctx).Tracef("GetPKCEAuthorizationFlow for pubKey %s took %v", req.WgPubKey, time.Since(start))
	}()

	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		errMSG := fmt.Sprintf("error while parsing peer's Wireguard public key %s on GetPKCEAuthorizationFlow request.", req.WgPubKey)
		log.WithContext(ctx).Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	err = encryption.DecryptMessage(peerKey, s.wgKey, req.Body, &proto.PKCEAuthorizationFlowRequest{})
	if err != nil {
		errMSG := fmt.Sprintf("error while decrypting peer's message with Wireguard public key %s.", req.WgPubKey)
		log.WithContext(ctx).Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	if s.config.PKCEAuthorizationFlow == nil {
		return nil, status.Error(codes.NotFound, "no pkce authorization flow information available")
	}

	initInfoFlow := &proto.PKCEAuthorizationFlow{
		ProviderConfig: &proto.ProviderConfig{
			Audience:              s.config.PKCEAuthorizationFlow.ProviderConfig.Audience,
			ClientID:              s.config.PKCEAuthorizationFlow.ProviderConfig.ClientID,
			ClientSecret:          s.config.PKCEAuthorizationFlow.ProviderConfig.ClientSecret,
			TokenEndpoint:         s.config.PKCEAuthorizationFlow.ProviderConfig.TokenEndpoint,
			AuthorizationEndpoint: s.config.PKCEAuthorizationFlow.ProviderConfig.AuthorizationEndpoint,
			Scope:                 s.config.PKCEAuthorizationFlow.ProviderConfig.Scope,
			RedirectURLs:          s.config.PKCEAuthorizationFlow.ProviderConfig.RedirectURLs,
			UseIDToken:            s.config.PKCEAuthorizationFlow.ProviderConfig.UseIDToken,
			DisablePromptLogin:    s.config.PKCEAuthorizationFlow.ProviderConfig.DisablePromptLogin,
			LoginFlag:             uint32(s.config.PKCEAuthorizationFlow.ProviderConfig.LoginFlag),
		},
	}

	flowInfoResp := s.integratedPeerValidator.ValidateFlowResponse(ctx, peerKey.String(), initInfoFlow)

	encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, flowInfoResp)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encrypt no pkce authorization flow information")
	}

	return &proto.EncryptedMessage{
		WgPubKey: s.wgKey.PublicKey().String(),
		Body:     encryptedResp,
	}, nil
}

// SyncMeta endpoint is used to synchronize peer's system metadata and notifies the connected,
// peer's under the same account of any updates.
func (s *GRPCServer) SyncMeta(ctx context.Context, req *proto.EncryptedMessage) (*proto.Empty, error) {
	realIP := getRealIP(ctx)
	log.WithContext(ctx).Debugf("Sync meta request from peer [%s] [%s]", req.WgPubKey, realIP.String())

	syncMetaReq := &proto.SyncMetaRequest{}
	peerKey, err := s.parseRequest(ctx, req, syncMetaReq)
	if err != nil {
		return nil, err
	}

	if syncMetaReq.GetMeta() == nil {
		msg := status.Errorf(codes.FailedPrecondition,
			"peer system meta has to be provided on sync. Peer %s, remote addr %s", peerKey.String(), realIP)
		log.WithContext(ctx).Warn(msg)
		return nil, msg
	}

	err = s.accountManager.SyncPeerMeta(ctx, peerKey.String(), extractPeerMeta(ctx, syncMetaReq.GetMeta()))
	if err != nil {
		return nil, mapError(ctx, err)
	}

	return &proto.Empty{}, nil
}

func (s *GRPCServer) Logout(ctx context.Context, req *proto.EncryptedMessage) (*proto.Empty, error) {
	log.WithContext(ctx).Debugf("Logout request from peer [%s]", req.WgPubKey)
	start := time.Now()

	empty := &proto.Empty{}
	peerKey, err := s.parseRequest(ctx, req, empty)
	if err != nil {
		return nil, err
	}

	peer, err := s.accountManager.GetStore().GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerKey.String())
	if err != nil {
		log.WithContext(ctx).Debugf("peer %s is not registered for logout", peerKey.String())
		// TODO: consider idempotency
		return nil, mapError(ctx, err)
	}

	// nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.PeerIDKey, peer.ID)
	// nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.AccountIDKey, peer.AccountID)

	userID := peer.UserID
	if userID == "" {
		userID = activity.SystemInitiator
	}

	if err = s.accountManager.DeletePeer(ctx, peer.AccountID, peer.ID, userID); err != nil {
		log.WithContext(ctx).Errorf("failed to logout peer %s: %v", peerKey.String(), err)
		return nil, mapError(ctx, err)
	}

	s.accountManager.BufferUpdateAccountPeers(ctx, peer.AccountID)

	log.WithContext(ctx).Debugf("peer %s logged out successfully after %s", peerKey.String(), time.Since(start))

	return &proto.Empty{}, nil
}

// toProtocolChecks converts posture checks to protocol checks.
func toProtocolChecks(ctx context.Context, postureChecks []*posture.Checks) []*proto.Checks {
	protoChecks := make([]*proto.Checks, 0, len(postureChecks))
	for _, postureCheck := range postureChecks {
		protoChecks = append(protoChecks, toProtocolCheck(postureCheck))
	}

	return protoChecks
}

// toProtocolCheck converts a posture.Checks to a proto.Checks.
func toProtocolCheck(postureCheck *posture.Checks) *proto.Checks {
	protoCheck := &proto.Checks{}

	if check := postureCheck.Checks.ProcessCheck; check != nil {
		for _, process := range check.Processes {
			if process.LinuxPath != "" {
				protoCheck.Files = append(protoCheck.Files, process.LinuxPath)
			}
			if process.MacPath != "" {
				protoCheck.Files = append(protoCheck.Files, process.MacPath)
			}
			if process.WindowsPath != "" {
				protoCheck.Files = append(protoCheck.Files, process.WindowsPath)
			}
		}
	}

	return protoCheck
}
