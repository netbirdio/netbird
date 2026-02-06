package grpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/golang/protobuf/proto" // nolint
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/shared/management/client/common"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/job"

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

const (
	envLogBlockedPeers = "NB_LOG_BLOCKED_PEERS"
	envBlockPeers      = "NB_BLOCK_SAME_PEERS"
	envConcurrentSyncs = "NB_MAX_CONCURRENT_SYNCS"

	defaultSyncLim = 1000
)

// Server an instance of a Management gRPC API server
type Server struct {
	accountManager  account.Manager
	settingsManager settings.Manager
	proto.UnimplementedManagementServiceServer
	jobManager     *job.Manager
	config         *nbconfig.Config
	secretsManager SecretsManager
	appMetrics     telemetry.AppMetrics
	peerLocks      sync.Map
	authManager    auth.Manager

	logBlockedPeers          bool
	blockPeersWithSameConfig bool
	integratedPeerValidator  integrated_validator.IntegratedValidator

	loginFilter *loginFilter

	networkMapController network_map.Controller

	oAuthConfigProvider idp.OAuthConfigProvider

	syncSem        atomic.Int32
	syncLimEnabled bool
	syncLim        int32
}

// NewServer creates a new Management server
func NewServer(
	config *nbconfig.Config,
	accountManager account.Manager,
	settingsManager settings.Manager,
	jobManager *job.Manager,
	secretsManager SecretsManager,
	appMetrics telemetry.AppMetrics,
	authManager auth.Manager,
	integratedPeerValidator integrated_validator.IntegratedValidator,
	networkMapController network_map.Controller,
	oAuthConfigProvider idp.OAuthConfigProvider,
) (*Server, error) {
	if appMetrics != nil {
		// update gauge based on number of connected peers which is equal to open gRPC streams
		err := appMetrics.GRPCMetrics().RegisterConnectedStreams(func() int64 {
			return int64(networkMapController.CountStreams())
		})
		if err != nil {
			return nil, err
		}
	}

	logBlockedPeers := strings.ToLower(os.Getenv(envLogBlockedPeers)) == "true"
	blockPeersWithSameConfig := strings.ToLower(os.Getenv(envBlockPeers)) == "true"

	syncLim := int32(defaultSyncLim)
	syncLimEnabled := true
	if syncLimStr := os.Getenv(envConcurrentSyncs); syncLimStr != "" {
		syncLimParsed, err := strconv.Atoi(syncLimStr)
		if err != nil {
			log.Errorf("invalid value for %s: %v using %d", envConcurrentSyncs, err, defaultSyncLim)
		} else {
			//nolint:gosec
			syncLim = int32(syncLimParsed)
			if syncLim < 0 {
				syncLimEnabled = false
			}
		}
	}

	return &Server{
		jobManager:               jobManager,
		accountManager:           accountManager,
		settingsManager:          settingsManager,
		config:                   config,
		secretsManager:           secretsManager,
		authManager:              authManager,
		appMetrics:               appMetrics,
		logBlockedPeers:          logBlockedPeers,
		blockPeersWithSameConfig: blockPeersWithSameConfig,
		integratedPeerValidator:  integratedPeerValidator,
		networkMapController:     networkMapController,
		oAuthConfigProvider:      oAuthConfigProvider,

		loginFilter: newLoginFilter(),

		syncLim:        syncLim,
		syncLimEnabled: syncLimEnabled,
	}, nil
}

func (s *Server) GetServerKey(ctx context.Context, req *proto.Empty) (*proto.ServerKeyResponse, error) {
	ip := ""
	p, ok := peer.FromContext(ctx)
	if ok {
		ip = p.Addr.String()
	}

	log.WithContext(ctx).Tracef("GetServerKey request from %s", ip)

	// todo introduce something more meaningful with the key expiration/rotation
	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountGetKeyRequest()
	}
	now := time.Now().Add(24 * time.Hour)
	secs := int64(now.Second())
	nanos := int32(now.Nanosecond())
	expiresAt := &timestamp.Timestamp{Seconds: secs, Nanos: nanos}

	key, err := s.secretsManager.GetWGKey()
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get wireguard key: %v", err)
		return nil, errors.New("failed to get wireguard key")
	}

	return &proto.ServerKeyResponse{
		Key:       key.PublicKey().String(),
		ExpiresAt: expiresAt,
	}, nil
}

func getRealIP(ctx context.Context) net.IP {
	if addr, ok := realip.FromContext(ctx); ok {
		return net.IP(addr.AsSlice())
	}
	return nil
}

func (s *Server) Job(srv proto.ManagementService_JobServer) error {
	reqStart := time.Now()
	ctx := srv.Context()

	peerKey, err := s.handleHandshake(ctx, srv)
	if err != nil {
		return err
	}

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
	peer, err := s.accountManager.GetStore().GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerKey.String())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "peer is not registered")
	}

	s.startResponseReceiver(ctx, srv)

	updates := s.jobManager.CreateJobChannel(ctx, accountID, peer.ID)
	log.WithContext(ctx).Debugf("Job: took %v", time.Since(reqStart))

	return s.sendJobsLoop(ctx, accountID, peerKey, peer, updates, srv)
}

// Sync validates the existence of a connecting peer, sends an initial state (all available for the connecting peers) and
// notifies the connected peer of any updates (e.g. new peers under the same account)
func (s *Server) Sync(req *proto.EncryptedMessage, srv proto.ManagementService_SyncServer) error {
	if s.syncLimEnabled && s.syncSem.Load() >= s.syncLim {
		return status.Errorf(codes.ResourceExhausted, "too many concurrent sync requests, please try again later")
	}
	s.syncSem.Add(1)

	reqStart := time.Now()

	ctx := srv.Context()

	syncReq := &proto.SyncRequest{}
	peerKey, err := s.parseRequest(ctx, req, syncReq)
	if err != nil {
		s.syncSem.Add(-1)
		return err
	}
	realIP := getRealIP(ctx)
	sRealIP := realIP.String()
	peerMeta := extractPeerMeta(ctx, syncReq.GetMeta())
	userID, err := s.accountManager.GetUserIDByPeerKey(ctx, peerKey.String())
	if err != nil {
		s.syncSem.Add(-1)
		if errStatus, ok := internalStatus.FromError(err); ok && errStatus.Type() == internalStatus.NotFound {
			return status.Errorf(codes.PermissionDenied, "peer is not registered")
		}
		return mapError(ctx, err)
	}

	metahashed := metaHash(peerMeta, sRealIP)
	if userID == "" && !s.loginFilter.allowLogin(peerKey.String(), metahashed) {
		if s.appMetrics != nil {
			s.appMetrics.GRPCMetrics().CountSyncRequestBlocked()
		}
		if s.logBlockedPeers {
			log.WithContext(ctx).Tracef("peer %s with meta hash %d is blocked from syncing", peerKey.String(), metahashed)
		}
		if s.blockPeersWithSameConfig {
			s.syncSem.Add(-1)
			return mapError(ctx, internalStatus.ErrPeerAlreadyLoggedIn)
		}
	}

	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountSyncRequest()
	}

	// nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.PeerIDKey, peerKey.String())

	accountID, err := s.accountManager.GetAccountIDForPeerKey(ctx, peerKey.String())
	if err != nil {
		// nolint:staticcheck
		ctx = context.WithValue(ctx, nbContext.AccountIDKey, "UNKNOWN")
		log.WithContext(ctx).Tracef("peer %s is not registered", peerKey.String())
		if errStatus, ok := internalStatus.FromError(err); ok && errStatus.Type() == internalStatus.NotFound {
			s.syncSem.Add(-1)
			return status.Errorf(codes.PermissionDenied, "peer is not registered")
		}
		s.syncSem.Add(-1)
		return err
	}

	// nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.AccountIDKey, accountID)

	start := time.Now()
	unlock := s.acquirePeerLockByUID(ctx, peerKey.String())
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	log.WithContext(ctx).Tracef("acquired peer lock for peer %s took %v", peerKey.String(), time.Since(start))

	log.WithContext(ctx).Debugf("Sync request from peer [%s] [%s]", req.WgPubKey, sRealIP)

	if syncReq.GetMeta() == nil {
		log.WithContext(ctx).Tracef("peer system meta has to be provided on sync. Peer %s, remote addr %s", peerKey.String(), realIP)
	}

	metahash := metaHash(peerMeta, realIP.String())
	s.loginFilter.addLogin(peerKey.String(), metahash)

	peer, netMap, postureChecks, dnsFwdPort, err := s.accountManager.SyncAndMarkPeer(ctx, accountID, peerKey.String(), peerMeta, realIP)
	if err != nil {
		log.WithContext(ctx).Debugf("error while syncing peer %s: %v", peerKey.String(), err)
		s.syncSem.Add(-1)
		return mapError(ctx, err)
	}

	err = s.sendInitialSync(ctx, peerKey, peer, netMap, postureChecks, srv, dnsFwdPort)
	if err != nil {
		log.WithContext(ctx).Debugf("error while sending initial sync for %s: %v", peerKey.String(), err)
		s.syncSem.Add(-1)
		s.cancelPeerRoutinesWithoutLock(ctx, accountID, peer)
		return err
	}

	updates, err := s.networkMapController.OnPeerConnected(ctx, accountID, peer.ID)
	if err != nil {
		log.WithContext(ctx).Debugf("error while notify peer connected for %s: %v", peerKey.String(), err)
		s.syncSem.Add(-1)
		s.cancelPeerRoutinesWithoutLock(ctx, accountID, peer)
		return err
	}

	s.secretsManager.SetupRefresh(ctx, accountID, peer.ID)

	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountSyncRequestDuration(time.Since(reqStart), accountID)
	}

	unlock()
	unlock = nil

	log.WithContext(ctx).Debugf("Sync took %s", time.Since(reqStart))

	s.syncSem.Add(-1)

	return s.handleUpdates(ctx, accountID, peerKey, peer, updates, srv)
}

func (s *Server) handleHandshake(ctx context.Context, srv proto.ManagementService_JobServer) (wgtypes.Key, error) {
	hello, err := srv.Recv()
	if err != nil {
		return wgtypes.Key{}, status.Errorf(codes.InvalidArgument, "missing hello: %v", err)
	}

	jobReq := &proto.JobRequest{}
	peerKey, err := s.parseRequest(ctx, hello, jobReq)
	if err != nil {
		return wgtypes.Key{}, err
	}

	return peerKey, nil
}

func (s *Server) startResponseReceiver(ctx context.Context, srv proto.ManagementService_JobServer) {
	go func() {
		for {
			msg, err := srv.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
					return
				}
				log.WithContext(ctx).Warnf("recv job response error: %v", err)
				return
			}

			jobResp := &proto.JobResponse{}
			if _, err := s.parseRequest(ctx, msg, jobResp); err != nil {
				log.WithContext(ctx).Warnf("invalid job response: %v", err)
				continue
			}

			if err := s.jobManager.HandleResponse(ctx, jobResp, msg.WgPubKey); err != nil {
				log.WithContext(ctx).Errorf("handle job response failed: %v", err)
			}
		}
	}()
}

func (s *Server) sendJobsLoop(ctx context.Context, accountID string, peerKey wgtypes.Key, peer *nbpeer.Peer, updates *job.Channel, srv proto.ManagementService_JobServer) error {
	// todo figure out better error handling strategy
	defer s.jobManager.CloseChannel(ctx, accountID, peer.ID)

	for {
		event, err := updates.Event(ctx)
		if err != nil {
			if errors.Is(err, job.ErrJobChannelClosed) {
				log.WithContext(ctx).Debugf("jobs channel for peer %s was closed", peerKey.String())
				return nil
			}

			// happens when connection drops, e.g. client disconnects
			log.WithContext(ctx).Debugf("stream of peer %s has been closed", peerKey.String())
			return ctx.Err()
		}

		if err := s.sendJob(ctx, peerKey, event, srv); err != nil {
			log.WithContext(ctx).Warnf("send job failed: %v", err)
			return nil
		}
	}
}

// handleUpdates sends updates to the connected peer until the updates channel is closed.
func (s *Server) handleUpdates(ctx context.Context, accountID string, peerKey wgtypes.Key, peer *nbpeer.Peer, updates chan *network_map.UpdateMessage, srv proto.ManagementService_SyncServer) error {
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
				s.cancelPeerRoutines(ctx, accountID, peer)
				return nil
			}
			log.WithContext(ctx).Debugf("received an update for peer %s", peerKey.String())
			if err := s.sendUpdate(ctx, accountID, peerKey, peer, update, srv); err != nil {
				log.WithContext(ctx).Debugf("error while sending an update to peer %s: %v", peerKey.String(), err)
				return err
			}

		// condition when client <-> server connection has been terminated
		case <-srv.Context().Done():
			// happens when connection drops, e.g. client disconnects
			log.WithContext(ctx).Debugf("stream of peer %s has been closed", peerKey.String())
			s.cancelPeerRoutines(ctx, accountID, peer)
			return srv.Context().Err()
		}
	}
}

// sendUpdate encrypts the update message using the peer key and the server's wireguard key,
// then sends the encrypted message to the connected peer via the sync server.
func (s *Server) sendUpdate(ctx context.Context, accountID string, peerKey wgtypes.Key, peer *nbpeer.Peer, update *network_map.UpdateMessage, srv proto.ManagementService_SyncServer) error {
	key, err := s.secretsManager.GetWGKey()
	if err != nil {
		s.cancelPeerRoutines(ctx, accountID, peer)
		return status.Errorf(codes.Internal, "failed processing update message")
	}

	encryptedResp, err := encryption.EncryptMessage(peerKey, key, update.Update)
	if err != nil {
		s.cancelPeerRoutines(ctx, accountID, peer)
		return status.Errorf(codes.Internal, "failed processing update message")
	}
	err = srv.Send(&proto.EncryptedMessage{
		WgPubKey: key.PublicKey().String(),
		Body:     encryptedResp,
	})
	if err != nil {
		s.cancelPeerRoutines(ctx, accountID, peer)
		return status.Errorf(codes.Internal, "failed sending update message")
	}
	log.WithContext(ctx).Debugf("sent an update to peer %s", peerKey.String())
	return nil
}

// sendJob encrypts the update message using the peer key and the server's wireguard key,
// then sends the encrypted message to the connected peer via the sync server.
func (s *Server) sendJob(ctx context.Context, peerKey wgtypes.Key, job *job.Event, srv proto.ManagementService_JobServer) error {
	wgKey, err := s.secretsManager.GetWGKey()
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get wg key for peer %s: %v", peerKey.String(), err)
		return status.Errorf(codes.Internal, "failed processing job message")
	}

	encryptedResp, err := encryption.EncryptMessage(peerKey, wgKey, job.Request)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to encrypt job for peer %s: %v", peerKey.String(), err)
		return status.Errorf(codes.Internal, "failed processing job message")
	}
	err = srv.Send(&proto.EncryptedMessage{
		WgPubKey: wgKey.PublicKey().String(),
		Body:     encryptedResp,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed sending job message")
	}
	log.WithContext(ctx).Debugf("sent a job to peer: %s", peerKey.String())
	return nil
}

func (s *Server) cancelPeerRoutines(ctx context.Context, accountID string, peer *nbpeer.Peer) {
	unlock := s.acquirePeerLockByUID(ctx, peer.Key)
	defer unlock()

	s.cancelPeerRoutinesWithoutLock(ctx, accountID, peer)
}

func (s *Server) cancelPeerRoutinesWithoutLock(ctx context.Context, accountID string, peer *nbpeer.Peer) {
	err := s.accountManager.OnPeerDisconnected(ctx, accountID, peer.Key)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to disconnect peer %s properly: %v", peer.Key, err)
	}
	s.networkMapController.OnPeerDisconnected(ctx, accountID, peer.ID)
	s.secretsManager.CancelRefresh(peer.ID)

	log.WithContext(ctx).Debugf("peer %s has been disconnected", peer.Key)
}

func (s *Server) validateToken(ctx context.Context, jwtToken string) (string, error) {
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

func (s *Server) acquirePeerLockByUID(ctx context.Context, uniqueID string) (unlock func()) {
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
	if errors.Is(err, internalStatus.ErrPeerAlreadyLoggedIn) {
		return status.Error(codes.PermissionDenied, internalStatus.ErrPeerAlreadyLoggedIn.Error())
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

func (s *Server) parseRequest(ctx context.Context, req *proto.EncryptedMessage, parsed pb.Message) (wgtypes.Key, error) {
	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		log.WithContext(ctx).Warnf("error while parsing peer's WireGuard public key %s.", req.WgPubKey)
		return wgtypes.Key{}, status.Errorf(codes.InvalidArgument, "provided wgPubKey %s is invalid", req.WgPubKey)
	}

	key, err := s.secretsManager.GetWGKey()
	if err != nil {
		return wgtypes.Key{}, status.Errorf(codes.Internal, "failed processing request")
	}

	err = encryption.DecryptMessage(peerKey, key, req.Body, parsed)
	if err != nil {
		return wgtypes.Key{}, status.Errorf(codes.InvalidArgument, "invalid request message")
	}

	return peerKey, nil
}

// Login endpoint first checks whether peer is registered under any account
// In case it is, the login is successful
// In case it isn't, the endpoint checks whether setup key is provided within the request and tries to register a peer.
// In case of the successful registration login is also successful
func (s *Server) Login(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	reqStart := time.Now()
	realIP := getRealIP(ctx)
	sRealIP := realIP.String()

	loginReq := &proto.LoginRequest{}
	peerKey, err := s.parseRequest(ctx, req, loginReq)
	if err != nil {
		return nil, err
	}

	peerMeta := extractPeerMeta(ctx, loginReq.GetMeta())
	metahashed := metaHash(peerMeta, sRealIP)
	if !s.loginFilter.allowLogin(peerKey.String(), metahashed) {
		if s.logBlockedPeers {
			log.WithContext(ctx).Tracef("peer %s with meta hash %d is blocked from login", peerKey.String(), metahashed)
		}
		if s.appMetrics != nil {
			s.appMetrics.GRPCMetrics().CountLoginRequestBlocked()
		}
		if s.blockPeersWithSameConfig {
			return nil, internalStatus.ErrPeerAlreadyLoggedIn
		}
	}

	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountLoginRequest()
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

	log.WithContext(ctx).Debugf("Login request from peer [%s] [%s]", req.WgPubKey, sRealIP)

	defer func() {
		if s.appMetrics != nil {
			s.appMetrics.GRPCMetrics().CountLoginRequestDuration(time.Since(reqStart), accountID)
		}
		log.WithContext(ctx).Debugf("Login took %s", time.Since(reqStart))
	}()

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
		Meta:            peerMeta,
		UserID:          userID,
		SetupKey:        loginReq.GetSetupKey(),
		ConnectionIP:    realIP,
		ExtraDNSLabels:  loginReq.GetDnsLabels(),
	})
	if err != nil {
		log.WithContext(ctx).Warnf("failed logging in peer %s: %s", peerKey, err)
		return nil, mapError(ctx, err)
	}

	loginResp, err := s.prepareLoginResponse(ctx, peer, netMap, postureChecks)
	if err != nil {
		log.WithContext(ctx).Warnf("failed preparing login response for peer %s: %s", peerKey, err)
		return nil, status.Errorf(codes.Internal, "failed logging in peer")
	}

	key, err := s.secretsManager.GetWGKey()
	if err != nil {
		log.WithContext(ctx).Warnf("failed getting server's WireGuard private key: %s", err)
		return nil, status.Errorf(codes.Internal, "failed logging in peer")
	}

	encryptedResp, err := encryption.EncryptMessage(peerKey, key, loginResp)
	if err != nil {
		log.WithContext(ctx).Warnf("failed encrypting peer %s message", peer.ID)
		return nil, status.Errorf(codes.Internal, "failed logging in peer")
	}

	return &proto.EncryptedMessage{
		WgPubKey: key.PublicKey().String(),
		Body:     encryptedResp,
	}, nil
}

func (s *Server) prepareLoginResponse(ctx context.Context, peer *nbpeer.Peer, netMap *types.NetworkMap, postureChecks []*posture.Checks) (*proto.LoginResponse, error) {
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
		PeerConfig:    toPeerConfig(peer, netMap.Network, s.networkMapController.GetDNSDomain(settings), settings, s.config.HttpConfig, s.config.DeviceAuthorizationFlow, netMap.EnableSSH),
		Checks:        toProtocolChecks(ctx, postureChecks),
	}

	return loginResp, nil
}

// processJwtToken validates the existence of a JWT token in the login request, and returns the corresponding user ID if
// the token is valid.
//
// The user ID can be empty if the token is not provided, which is acceptable if the peer is already
// registered or if it uses a setup key to register.
func (s *Server) processJwtToken(ctx context.Context, loginReq *proto.LoginRequest, peerKey wgtypes.Key) (string, error) {
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

// IsHealthy indicates whether the service is healthy
func (s *Server) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

// sendInitialSync sends initial proto.SyncResponse to the peer requesting synchronization
func (s *Server) sendInitialSync(ctx context.Context, peerKey wgtypes.Key, peer *nbpeer.Peer, networkMap *types.NetworkMap, postureChecks []*posture.Checks, srv proto.ManagementService_SyncServer, dnsFwdPort int64) error {
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

	peerGroups, err := s.accountManager.GetStore().GetPeerGroupIDs(ctx, store.LockingStrengthNone, peer.AccountID, peer.ID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get peer groups %s", err)
	}

	plainResp := ToSyncResponse(ctx, s.config, s.config.HttpConfig, s.config.DeviceAuthorizationFlow, peer, turnToken, relayToken, networkMap, s.networkMapController.GetDNSDomain(settings), postureChecks, nil, settings, settings.Extra, peerGroups, dnsFwdPort)

	key, err := s.secretsManager.GetWGKey()
	if err != nil {
		return status.Errorf(codes.Internal, "failed getting server key")
	}

	encryptedResp, err := encryption.EncryptMessage(peerKey, key, plainResp)
	if err != nil {
		return status.Errorf(codes.Internal, "error handling request")
	}

	err = srv.Send(&proto.EncryptedMessage{
		WgPubKey: key.PublicKey().String(),
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
func (s *Server) GetDeviceAuthorizationFlow(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	log.WithContext(ctx).Tracef("GetDeviceAuthorizationFlow request for pubKey: %s", req.WgPubKey)

	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		errMSG := fmt.Sprintf("error while parsing peer's Wireguard public key %s on GetDeviceAuthorizationFlow request.", req.WgPubKey)
		log.WithContext(ctx).Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	key, err := s.secretsManager.GetWGKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get server key")
	}

	err = encryption.DecryptMessage(peerKey, key, req.Body, &proto.DeviceAuthorizationFlowRequest{})
	if err != nil {
		errMSG := fmt.Sprintf("error while decrypting peer's message with Wireguard public key %s.", req.WgPubKey)
		log.WithContext(ctx).Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	var flowInfoResp *proto.DeviceAuthorizationFlow

	// Use embedded IdP configuration if available
	if s.oAuthConfigProvider != nil {
		flowInfoResp = &proto.DeviceAuthorizationFlow{
			Provider: proto.DeviceAuthorizationFlow_HOSTED,
			ProviderConfig: &proto.ProviderConfig{
				ClientID:           s.oAuthConfigProvider.GetCLIClientID(),
				Audience:           s.oAuthConfigProvider.GetCLIClientID(),
				DeviceAuthEndpoint: s.oAuthConfigProvider.GetDeviceAuthEndpoint(),
				TokenEndpoint:      s.oAuthConfigProvider.GetTokenEndpoint(),
				Scope:              s.oAuthConfigProvider.GetDefaultScopes(),
			},
		}
	} else {
		if s.config.DeviceAuthorizationFlow == nil || s.config.DeviceAuthorizationFlow.Provider == string(nbconfig.NONE) {
			return nil, status.Error(codes.NotFound, "no device authorization flow information available")
		}

		provider, ok := proto.DeviceAuthorizationFlowProvider_value[strings.ToUpper(s.config.DeviceAuthorizationFlow.Provider)]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "no provider found in the protocol for %s", s.config.DeviceAuthorizationFlow.Provider)
		}

		flowInfoResp = &proto.DeviceAuthorizationFlow{
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
	}

	encryptedResp, err := encryption.EncryptMessage(peerKey, key, flowInfoResp)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encrypt device authorization flow information")
	}

	return &proto.EncryptedMessage{
		WgPubKey: key.PublicKey().String(),
		Body:     encryptedResp,
	}, nil
}

// GetPKCEAuthorizationFlow returns a pkce authorization flow information
// This is used for initiating an Oauth 2 pkce authorization grant flow
// which will be used by our clients to Login
func (s *Server) GetPKCEAuthorizationFlow(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	log.WithContext(ctx).Tracef("GetPKCEAuthorizationFlow request for pubKey: %s", req.WgPubKey)

	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		errMSG := fmt.Sprintf("error while parsing peer's Wireguard public key %s on GetPKCEAuthorizationFlow request.", req.WgPubKey)
		log.WithContext(ctx).Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	key, err := s.secretsManager.GetWGKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get server key")
	}

	err = encryption.DecryptMessage(peerKey, key, req.Body, &proto.PKCEAuthorizationFlowRequest{})
	if err != nil {
		errMSG := fmt.Sprintf("error while decrypting peer's message with Wireguard public key %s.", req.WgPubKey)
		log.WithContext(ctx).Warn(errMSG)
		return nil, status.Error(codes.InvalidArgument, errMSG)
	}

	var initInfoFlow *proto.PKCEAuthorizationFlow

	// Use embedded IdP configuration if available
	if s.oAuthConfigProvider != nil {
		initInfoFlow = &proto.PKCEAuthorizationFlow{
			ProviderConfig: &proto.ProviderConfig{
				Audience:              s.oAuthConfigProvider.GetCLIClientID(),
				ClientID:              s.oAuthConfigProvider.GetCLIClientID(),
				TokenEndpoint:         s.oAuthConfigProvider.GetTokenEndpoint(),
				AuthorizationEndpoint: s.oAuthConfigProvider.GetAuthorizationEndpoint(),
				Scope:                 s.oAuthConfigProvider.GetDefaultScopes(),
				RedirectURLs:          s.oAuthConfigProvider.GetCLIRedirectURLs(),
				LoginFlag:             uint32(common.LoginFlagPromptLogin),
			},
		}
	} else {
		if s.config.PKCEAuthorizationFlow == nil {
			return nil, status.Error(codes.NotFound, "no pkce authorization flow information available")
		}

		initInfoFlow = &proto.PKCEAuthorizationFlow{
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
	}

	flowInfoResp := s.integratedPeerValidator.ValidateFlowResponse(ctx, peerKey.String(), initInfoFlow)

	encryptedResp, err := encryption.EncryptMessage(peerKey, key, flowInfoResp)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encrypt pkce authorization flow information")
	}

	return &proto.EncryptedMessage{
		WgPubKey: key.PublicKey().String(),
		Body:     encryptedResp,
	}, nil
}

// SyncMeta endpoint is used to synchronize peer's system metadata and notifies the connected,
// peer's under the same account of any updates.
func (s *Server) SyncMeta(ctx context.Context, req *proto.EncryptedMessage) (*proto.Empty, error) {
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

func (s *Server) Logout(ctx context.Context, req *proto.EncryptedMessage) (*proto.Empty, error) {
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
