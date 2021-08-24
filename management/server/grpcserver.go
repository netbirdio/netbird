package server

import (
	"context"
	"fmt"
	"sync"
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
	peerChannels map[string]chan *UpdateChannelMessage
	channelsMux  *sync.Mutex
	config       *Config
}

// AllowedIPsFormat generates Wireguard AllowedIPs format (e.g. 100.30.30.1/32)
const AllowedIPsFormat = "%s/32"

type UpdateChannelMessage struct {
	Update *proto.SyncResponse
}

// NewServer creates a new Management server
func NewServer(config *Config, accountManager *AccountManager) (*Server, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return &Server{
		wgKey: key,
		// peerKey -> event channel
		peerChannels:   make(map[string]chan *UpdateChannelMessage),
		channelsMux:    &sync.Mutex{},
		accountManager: accountManager,
		config:         config,
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

	updates := s.openUpdatesChannel(peerKey.String())

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
		// condition when client <-> server connection has been terminated
		case <-srv.Context().Done():
			// happens when connection drops, e.g. client disconnects
			log.Debugf("stream of peer %s has been closed", peerKey.String())
			s.closeUpdatesChannel(peerKey.String())
			return srv.Context().Err()
		}
	}
}

func (s *Server) registerPeer(peerKey wgtypes.Key, req *proto.LoginRequest) (*Peer, error) {
	s.channelsMux.Lock()
	defer s.channelsMux.Unlock()

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

	peers, err := s.accountManager.GetPeersForAPeer(peer.Key)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}

	// notify other peers of our registration
	for _, remotePeer := range peers {
		if channel, ok := s.peerChannels[remotePeer.Key]; ok {
			// exclude notified peer and add ourselves
			peersToSend := []*Peer{peer}
			for _, p := range peers {
				if remotePeer.Key != p.Key {
					peersToSend = append(peersToSend, p)
				}
			}
			update := toSyncResponse(s.config, peer, peersToSend)
			channel <- &UpdateChannelMessage{Update: update}
		}
	}

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
		WiretrusteeConfig: toWiretrusteeConfig(s.config),
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

func toResponseProto(configProto Protocol) proto.HostConfig_Protocol {
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

func toWiretrusteeConfig(config *Config) *proto.WiretrusteeConfig {

	var stuns []*proto.HostConfig
	for _, stun := range config.Stuns {
		stuns = append(stuns, &proto.HostConfig{
			Uri:      stun.URI,
			Protocol: toResponseProto(stun.Proto),
		})
	}
	var turns []*proto.ProtectedHostConfig
	for _, turn := range config.Turns {
		turns = append(turns, &proto.ProtectedHostConfig{
			HostConfig: &proto.HostConfig{
				Uri:      turn.URI,
				Protocol: toResponseProto(turn.Proto),
			},
			User:     turn.Username,
			Password: string(turn.Password),
		})
	}

	return &proto.WiretrusteeConfig{
		Stuns: stuns,
		Turns: turns,
		Signal: &proto.HostConfig{
			Uri:      config.Signal.URI,
			Protocol: toResponseProto(config.Signal.Proto),
		},
	}
}

func toPeerConfig(peer *Peer) *proto.PeerConfig {
	return &proto.PeerConfig{
		Address: peer.IP.String() + "/24", //todo make it explicit
	}
}

func toSyncResponse(config *Config, peer *Peer, peers []*Peer) *proto.SyncResponse {

	wtConfig := toWiretrusteeConfig(config)

	pConfig := toPeerConfig(peer)

	remotePeers := make([]*proto.RemotePeerConfig, 0, len(peers))
	for _, rPeer := range peers {
		remotePeers = append(remotePeers, &proto.RemotePeerConfig{
			WgPubKey:   rPeer.Key,
			AllowedIps: []string{fmt.Sprintf(AllowedIPsFormat, rPeer.IP)}, //todo /32
		})
	}

	return &proto.SyncResponse{
		WiretrusteeConfig: wtConfig,
		PeerConfig:        pConfig,
		RemotePeers:       remotePeers,
	}
}

// IsHealthy indicates whether the service is healthy
func (s *Server) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

// openUpdatesChannel creates a go channel for a given peer used to deliver updates relevant to the peer.
func (s *Server) openUpdatesChannel(peerKey string) chan *UpdateChannelMessage {
	s.channelsMux.Lock()
	defer s.channelsMux.Unlock()
	if channel, ok := s.peerChannels[peerKey]; ok {
		delete(s.peerChannels, peerKey)
		close(channel)
	}
	//mbragin: todo shouldn't it be more? or configurable?
	channel := make(chan *UpdateChannelMessage, 100)
	s.peerChannels[peerKey] = channel

	err := s.accountManager.MarkPeerConnected(peerKey, true)
	if err != nil {
		log.Warnf("failed marking peer as connected %s %v", peerKey, err)
	}

	log.Debugf("opened updates channel for a peer %s", peerKey)
	return channel
}

// closeUpdatesChannel closes updates channel of a given peer
func (s *Server) closeUpdatesChannel(peerKey string) {
	s.channelsMux.Lock()
	defer s.channelsMux.Unlock()
	if channel, ok := s.peerChannels[peerKey]; ok {
		delete(s.peerChannels, peerKey)
		close(channel)
	}

	err := s.accountManager.MarkPeerConnected(peerKey, false)
	if err != nil {
		log.Warnf("failed marking peer as disconnected %s %v", peerKey, err)
	}

	log.Debugf("closed updates channel of a peer %s", peerKey)
}

// sendInitialSync sends initial proto.SyncResponse to the peer requesting synchronization
func (s *Server) sendInitialSync(peerKey wgtypes.Key, peer *Peer, srv proto.ManagementService_SyncServer) error {

	peers, err := s.accountManager.GetPeersForAPeer(peer.Key)
	if err != nil {
		log.Warnf("error getting a list of peers for a peer %s", peer.Key)
		return err
	}
	plainResp := toSyncResponse(s.config, peer, peers)

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
