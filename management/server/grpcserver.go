package server

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/encryption"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server an instance of a Management server
type Server struct {
	accountManager *AccountManager
	wgKey          wgtypes.Key
	proto.UnimplementedManagementServiceServer
	peersUpdateManager     *PeersUpdateManager
	config                 *Config
	turnCredentialsManager TURNCredentialsManager
}

// AllowedIPsFormat generates Wireguard AllowedIPs format (e.g. 100.30.30.1/32)
const AllowedIPsFormat = "%s/32"

// NewServer creates a new Management server
func NewServer(config *Config, accountManager *AccountManager, peersUpdateManager *PeersUpdateManager, turnCredentialsManager TURNCredentialsManager) (*Server, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	return &Server{
		wgKey: key,
		// peerKey -> event channel
		peersUpdateManager:     peersUpdateManager,
		accountManager:         accountManager,
		config:                 config,
		turnCredentialsManager: turnCredentialsManager,
	}, nil
}

func (s *Server) GetServerKey(ctx context.Context, req *proto.Empty) (*proto.ServerKeyResponse, error) {

	// todo introduce something more meaningful with the key expiration/rotation
	now := time.Now().Add(24 * time.Hour)
	secs := int64(now.Second())
	nanos := int32(now.Nanosecond())
	expiresAt := &timestamp.Timestamp{Seconds: secs, Nanos: nanos}

	return &proto.ServerKeyResponse{
		Key:       s.wgKey.PublicKey().String(),
		ExpiresAt: expiresAt,
	}, nil
}

//Sync validates the existence of a connecting peer, sends an initial state (all available for the connecting peers) and
// notifies the connected peer of any updates (e.g. new peers under the same account)
func (s *Server) Sync(req *proto.EncryptedMessage, srv proto.ManagementService_SyncServer) error {

	log.Debugf("Sync request from peer %s", req.WgPubKey)

	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		log.Warnf("error while parsing peer's Wireguard public key %s on Sync request.", peerKey.String())
		return status.Errorf(codes.InvalidArgument, "provided wgPubKey %s is invalid", peerKey.String())
	}

	peer, err := s.accountManager.GetPeer(peerKey.String())
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "provided peer with the key wgPubKey %s is not registered", peerKey.String())
	}

	syncReq := &proto.SyncRequest{}
	err = encryption.DecryptMessage(peerKey, s.wgKey, req.Body, syncReq)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid request message")
	}

	err = s.sendInitialSync(peerKey, peer, srv)
	if err != nil {
		return err
	}

	updates := s.peersUpdateManager.CreateChannel(peerKey.String())
	err = s.accountManager.MarkPeerConnected(peerKey.String(), true)
	if err != nil {
		log.Warnf("failed marking peer as connected %s %v", peerKey, err)
	}

	if s.config.TURNConfig.TimeBasedCredentials {
		s.turnCredentialsManager.SetupRefresh(peerKey.String())
	}

	s.schedulePeerUpdates(srv.Context(), peerKey.String(), peer)
	// keep a connection to the peer and send updates when available
	for {
		select {
		// condition when there are some updates
		case update, open := <-updates:
			if !open {
				// updates channel has been closed
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
			s.peersUpdateManager.CloseChannel(peerKey.String())
			s.turnCredentialsManager.CancelRefresh(peerKey.String())
			err = s.accountManager.MarkPeerConnected(peerKey.String(), false)
			if err != nil {
				log.Warnf("failed marking peer as disconnected %s %v", peerKey, err)
			}
			// todo stop turn goroutine
			return srv.Context().Err()
		}
	}
}

func (s *Server) schedulePeerUpdates(context context.Context, peerKey string, peer *Peer) {
	//todo: introduce the following logic:
	// add a ModificationId to the Account entity (ModificationId increments by 1 if there was a change to the account network map)
	// periodically fetch changes of the Account providing ModificationId
	// if ModificationId is < then the one of the Account, then send changes
	// Client has to handle modification id as well
	go func() {
		for {
			select {
			case <-context.Done():
				log.Debugf("peer update cancelled %s", peerKey)
				return
			default:
				maxSleep := 6
				minSleep := 3
				sleep := rand.Intn(maxSleep-minSleep) + minSleep
				time.Sleep(time.Duration(sleep) * time.Second)

				peers, err := s.accountManager.GetPeersForAPeer(peerKey)
				if err != nil {
					continue
				}

				update := toSyncResponse(s.config, peer, peers, nil)
				err = s.peersUpdateManager.SendUpdate(peerKey, &UpdateMessage{Update: update})
				if err != nil {
					continue
				}
			}
		}
	}()
}

func (s *Server) registerPeer(peerKey wgtypes.Key, req *proto.LoginRequest) (*Peer, error) {

	meta := req.GetMeta()
	if meta == nil {
		return nil, status.Errorf(codes.InvalidArgument, "peer meta data was not provided")
	}
	peer, err := s.accountManager.AddPeer(req.GetSetupKey(), Peer{
		Key:  peerKey.String(),
		Name: meta.GetHostname(),
		Meta: PeerSystemMeta{
			Hostname:  meta.GetHostname(),
			GoOS:      meta.GetGoOS(),
			Kernel:    meta.GetKernel(),
			Core:      meta.GetCore(),
			Platform:  meta.GetPlatform(),
			OS:        meta.GetOS(),
			WtVersion: meta.GetWiretrusteeVersion(),
		},
	})
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "provided setup key doesn't exists")
	}

	// notify other peers of our registration - uncomment if you want to bring back peer update logic
	/*peers, err := s.accountManager.GetPeersForAPeer(peer.Key)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}


	for _, remotePeer := range peers {
		// exclude notified peer and add ourselves
		peersToSend := []*Peer{peer}
		for _, p := range peers {
			if remotePeer.Key != p.Key {
				peersToSend = append(peersToSend, p)
			}
		}
		update := toSyncResponse(s.config, peer, peersToSend, nil)
		err = s.peersUpdateManager.SendUpdate(remotePeer.Key, &UpdateMessage{Update: update})
		if err != nil {
			// todo rethink if we should keep this return
			return nil, err
		}
	}*/

	return peer, nil
}

// Login endpoint first checks whether peer is registered under any account
// In case it is, the login is successful
// In case it isn't, the endpoint checks whether setup key is provided within the request and tries to register a peer.
// In case of the successful registration login is also successful
func (s *Server) Login(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {

	log.Debugf("Login request from peer %s", req.WgPubKey)

	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		log.Warnf("error while parsing peer's Wireguard public key %s on Sync request.", req.WgPubKey)
		return nil, status.Errorf(codes.InvalidArgument, "provided wgPubKey %s is invalid", req.WgPubKey)
	}

	peer, err := s.accountManager.GetPeer(peerKey.String())
	if err != nil {
		if errStatus, ok := status.FromError(err); ok && errStatus.Code() == codes.NotFound {
			//peer doesn't exist -> check if setup key was provided
			loginReq := &proto.LoginRequest{}
			err = encryption.DecryptMessage(peerKey, s.wgKey, req.Body, loginReq)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid request message")
			}

			if loginReq.GetSetupKey() == "" {
				//absent setup key -> permission denied
				return nil, status.Errorf(codes.PermissionDenied, "provided peer with the key wgPubKey %s is not registered", peerKey.String())
			}

			//setup key is present -> try normal registration flow
			peer, err = s.registerPeer(peerKey, loginReq)
			if err != nil {
				return nil, err
			}

		} else {
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// if peer has reached this point then it has logged in
	loginResp := &proto.LoginResponse{
		WiretrusteeConfig: toWiretrusteeConfig(s.config, nil),
		PeerConfig:        toPeerConfig(peer),
	}
	encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, loginResp)
	if err != nil {
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
		//mbragin: todo something better?
		panic(fmt.Errorf("unexpected config protocol type %v", configProto))
	}
}

func toWiretrusteeConfig(config *Config, turnCredentials *TURNCredentials) *proto.WiretrusteeConfig {

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

func toPeerConfig(peer *Peer) *proto.PeerConfig {
	return &proto.PeerConfig{
		Address: peer.IP.String() + "/24", //todo make it explicit
	}
}

func toRemotePeerConfig(peers []*Peer) []*proto.RemotePeerConfig {

	remotePeers := []*proto.RemotePeerConfig{}
	for _, rPeer := range peers {
		remotePeers = append(remotePeers, &proto.RemotePeerConfig{
			WgPubKey:   rPeer.Key,
			AllowedIps: []string{fmt.Sprintf(AllowedIPsFormat, rPeer.IP)}, //todo /32
		})
	}

	return remotePeers

}

func toSyncResponse(config *Config, peer *Peer, peers []*Peer, turnCredentials *TURNCredentials) *proto.SyncResponse {

	wtConfig := toWiretrusteeConfig(config, turnCredentials)

	pConfig := toPeerConfig(peer)

	remotePeers := toRemotePeerConfig(peers)

	return &proto.SyncResponse{
		WiretrusteeConfig:  wtConfig,
		PeerConfig:         pConfig,
		RemotePeers:        remotePeers,
		RemotePeersIsEmpty: len(remotePeers) == 0,
	}
}

// IsHealthy indicates whether the service is healthy
func (s *Server) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

// sendInitialSync sends initial proto.SyncResponse to the peer requesting synchronization
func (s *Server) sendInitialSync(peerKey wgtypes.Key, peer *Peer, srv proto.ManagementService_SyncServer) error {

	peers, err := s.accountManager.GetPeersForAPeer(peer.Key)
	if err != nil {
		log.Warnf("error getting a list of peers for a peer %s", peer.Key)
		return err
	}

	// make secret time based TURN credentials optional
	var turnCredentials *TURNCredentials
	if s.config.TURNConfig.TimeBasedCredentials {
		creds := s.turnCredentialsManager.GenerateCredentials()
		turnCredentials = &creds
	} else {
		turnCredentials = nil
	}
	plainResp := toSyncResponse(s.config, peer, peers, turnCredentials)

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
